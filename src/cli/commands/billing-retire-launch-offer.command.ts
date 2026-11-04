import { Logger } from '@nestjs/common';
import { Command, CommandRunner } from 'nest-commander';
import { PRICE, StripeGateway } from '../../billing/stripe.gateway';
import { ControlPrismaService } from '../../database/control-prisma.service';

/**
 * `pnpm manar billing:retire-launch-offer` (workspace spec 2026-11-04-payg, section 8). The launch
 * offer's free Pro months were a Stripe trial on the old $9 price. So that nobody is ever charged
 * $9: a trial with no card is set to end without renewing (`cancel_at_period_end`), and a trial
 * whose owner already chose "Keep Pro" moves to the new $5 Pro price with the extra-device item.
 * Idempotent; prints counts only.
 */
@Command({
  name: 'billing:retire-launch-offer',
  description: 'End or re-price the launch-offer Pro trials (old $9 price)',
})
export class BillingRetireLaunchOfferCommand extends CommandRunner {
  private readonly logger = new Logger(BillingRetireLaunchOfferCommand.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly stripe: StripeGateway,
  ) {
    super();
  }

  async run(): Promise<void> {
    const claims = await this.control.launchOfferClaim.findMany({
      where: { stripeSubscriptionId: { not: null } },
    });
    const stripe = this.stripe.client();
    const [pro, extra] = await Promise.all([
      this.stripe.price(PRICE.PRO_MONTHLY),
      this.stripe.price(PRICE.PRO_EXTRA_DEVICE),
    ]);
    const n = { ending: 0, repriced: 0, skipped: 0, failed: 0 };
    for (const c of claims) {
      try {
        const sub = await stripe.subscriptions.retrieve(
          c.stripeSubscriptionId!,
        );
        if (!['trialing', 'active', 'past_due'].includes(sub.status)) {
          n.skipped++;
          continue;
        }
        const old = sub.items.data.find(
          (i) => !i.price.lookup_key?.startsWith('manar_pro_'),
        );
        if (!old) {
          n.skipped++; // already on the new prices
          continue;
        }
        if (!c.keptAt) {
          if (!sub.cancel_at_period_end)
            await stripe.subscriptions.update(sub.id, {
              cancel_at_period_end: true,
            });
          n.ending++;
          continue;
        }
        await stripe.subscriptions.update(
          sub.id,
          {
            items: [{ id: old.id, price: pro, quantity: 1 }, { price: extra }],
            proration_behavior: 'none',
          },
          { idempotencyKey: `manar-retire-launch-${sub.id}` },
        );
        n.repriced++;
      } catch (error) {
        n.failed++;
        this.logger.warn(`claim ${c.id}: ${String(error)}`);
      }
    }
    this.logger.log(
      `launch offer: ${n.ending} ending, ${n.repriced} moved to $5 Pro, ${n.skipped} skipped, ${n.failed} failed`,
    );
  }
}
