import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import { BillableUsageService } from './billable-usage.service';
import { StripeGateway } from './stripe.gateway';

/**
 * Daily: counts each Company tenant's billable users and extra devices and sets the quantities on
 * its two subscription items. Setting a quantity to the value it already has changes nothing, so
 * overlapping replicas and restarts are harmless (ponytail: no lease; add one if Stripe call
 * volume ever matters).
 */
@Injectable()
export class CompanyQuantityService implements OnModuleInit, OnModuleDestroy {
  static readonly INTERVAL_MS = 24 * 60 * 60 * 1000;
  private readonly logger = new Logger(CompanyQuantityService.name);
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private readonly control: ControlPrismaService,
    private readonly usage: BillableUsageService,
    private readonly stripe: StripeGateway,
  ) {}

  onModuleInit(): void {
    if (!this.stripe.configured) return;
    const tick = () => {
      this.timer = setTimeout(() => {
        void this.runAll().finally(tick);
      }, CompanyQuantityService.INTERVAL_MS);
    };
    // First pass a minute after start, so a deploy never waits a day for correct quantities.
    this.timer = setTimeout(() => {
      void this.runAll().finally(tick);
    }, 60_000);
  }

  onModuleDestroy(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  async runAll(): Promise<void> {
    const rows = await this.control.tenantEntitlement.findMany({
      where: { plan: 'company', stripeSubscriptionId: { not: null } },
      select: { tenantId: true, stripeSubscriptionId: true },
    });
    for (const row of rows) {
      try {
        await this.syncTenant(row.tenantId, row.stripeSubscriptionId!);
      } catch (error) {
        this.logger.error(
          `Company quantities failed for tenant "${row.tenantId}": ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  async syncTenant(tenantId: string, subscriptionId: string): Promise<void> {
    const userPrice = this.stripe.price('COMPANY_USER');
    const devicePrice = this.stripe.price('EXTRA_DEVICE');
    if (!userPrice || !devicePrice) return;
    const { users, extraDevices } = await this.usage.billable(tenantId);
    const stripe = this.stripe.client();
    const sub = await stripe.subscriptions.retrieve(subscriptionId);
    const userItem = sub.items.data.find((i) => i.price.id === userPrice);
    const deviceItem = sub.items.data.find((i) => i.price.id === devicePrice);
    // A Company workspace always pays for at least one user.
    const wantUsers = Math.max(1, users);
    if (userItem && userItem.quantity !== wantUsers)
      await stripe.subscriptionItems.update(userItem.id, {
        quantity: wantUsers,
        proration_behavior: 'create_prorations',
      });
    if (deviceItem) {
      if (deviceItem.quantity !== extraDevices)
        await stripe.subscriptionItems.update(deviceItem.id, {
          quantity: extraDevices,
          proration_behavior: 'create_prorations',
        });
    } else if (extraDevices > 0) {
      await stripe.subscriptionItems.create({
        subscription: subscriptionId,
        price: devicePrice,
        quantity: extraDevices,
        proration_behavior: 'create_prorations',
      });
    }
  }
}
