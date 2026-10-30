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
    const run = () =>
      this.runAll()
        .catch((error: unknown) =>
          this.logger.error(`Company quantity round failed: ${String(error)}`),
        )
        .finally(() => {
          this.timer = setTimeout(
            () => void run(),
            CompanyQuantityService.INTERVAL_MS,
          );
        });
    // First pass a minute after start, so a deploy never waits a day for correct quantities.
    this.timer = setTimeout(() => void run(), 60_000);
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
    const stripe = this.stripe.client();
    const sub = await stripe.subscriptions.retrieve(subscriptionId);
    const userItem = sub.items.data.find((i) => i.price.id === userPrice);
    const deviceItem = sub.items.data.find((i) => i.price.id === devicePrice);
    // Count over the billing period the subscription is in, not the calendar month.
    const since = userItem
      ? new Date(userItem.current_period_start * 1000)
      : undefined;
    const { users, extraDevices } = await this.usage.billable(tenantId, since);
    // A Company workspace always pays for at least one user.
    const wantUsers = Math.max(1, users);
    // Mid-period only raises are charged (prorated); a decrease takes effect at renewal, unprorated.
    const set = (itemId: string, have: number, want: number) =>
      have === want
        ? Promise.resolve()
        : stripe.subscriptionItems.update(itemId, {
            quantity: want,
            proration_behavior: want > have ? 'create_prorations' : 'none',
          });
    if (userItem) await set(userItem.id, userItem.quantity ?? 0, wantUsers);
    if (deviceItem) {
      await set(deviceItem.id, deviceItem.quantity ?? 0, extraDevices);
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
