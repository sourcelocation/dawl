# dawl

Subscriptions from every store, in one vocabulary. dawl verifies what Stripe, the App Store, Google Play and Discord report about a subscription and normalises it into a single `subscription.State`, with one rule for how long it grants access.

It is the store-facing half of billing, shared by [Rondo](https://github.com/sourcelocation/rondo) and [Invarn](https://github.com/sourcelocation/invarn). Plans, limits, storage and what an app does when a plan changes stay in each app.

| Package | What it does |
| --- | --- |
| [`subscription`](subscription) | `Provider`, `Status`, `State` with `Until` and `Entitles`, `Price`, the `Gateway`, `Renewer` and `Catalog` interfaces, `Webhook`, and the errors gateways return. Standard library only, so apps can use it from their domain layer. |
| [`stripe`](stripe) | Customers, Checkout, the customer portal, webhook verification, subscription state, renewal off and on, prices. |
| [`appstore`](appstore) | StoreKit 2 transactions and App Store Server Notifications V2, verified against Apple's root certificate; subscription status from the App Store Server API (production, then sandbox). |
| [`googleplay`](googleplay) | Subscription state and acknowledgement from the Android Publisher API; Real-time Developer Notifications verified from their Pub/Sub push. |
| [`discord`](discord) | App subscriptions as entitlements from Discord's API; Webhook Events verified by their Ed25519 signature. |

Every gateway is a `subscription.Gateway`: `Verify` checks proof from an app's purchase, and
`Notification` reads a store's notification. Stores deliver notifications late and out of order, so
`Notification` always returns the subscription as the store has it now: saving it is safe in any
order. `subscription.Webhook` serves notifications for any gateway:

```go
var gw subscription.Gateway = stripe.New(stripe.Config{SecretKey: key, WebhookSecret: whsec, AccountMetadataKey: "app_account"})

http.Handle("POST /webhooks/stripe", subscription.Webhook(gw, func(ctx context.Context, s subscription.State) error {
	return save(ctx, s.Account, s) // then: s.Until() or s.Entitles(time.Now())
}))

state, err := appStore.Verify(ctx, signedTransaction) // from StoreKit 2, in an app's request
```

`State.Until` is when a subscription stops granting access: its period end, plus `subscription.Grace` while the store may still renew it. An app that keeps "access until" stores the latest `Until` of a person's subscriptions; access it grants itself (gifts, codes) fits as an active subscription with renewal off. A store that grants access with no end set yet reports `subscription.Forever` as the period end: Discord keeps an entitlement going until the subscription ends, and only then sets an end.

`State.Account` is who bought a subscription. `State.Covers` is what it grants access to when that is something else: a Discord guild subscription is bought by a person and covers their server.

A gateway that can say what its products cost is also a `subscription.Catalog`, for showing prices before someone buys (Stripe's is; the other stores show their own prices where people buy):

```go
if c, ok := gw.(subscription.Catalog); ok {
	prices, err := c.Prices(ctx, monthlyPriceID, yearlyPriceID) // Amount in cents, Currency, Interval, Every
}
```

A gateway that can turn renewal off and on from the server is also a `subscription.Renewer` (Stripe's is; the App Store, Google Play and Discord leave that to the person):

```go
if r, ok := gw.(subscription.Renewer); ok {
	err = r.SetAutoRenew(ctx, state.ProviderRef, false) // the paid period stays
}
```

Every gateway wraps failures in one of the `subscription.Err*` values (`ErrUnverified`, `ErrNotSubscription`, `ErrInvalidNotification`, `ErrMalformed`, `ErrNotFound`, `ErrUnavailable`), so an app maps them onto its own errors with `errors.Is`. `State.Account` is the app's account id as the store carries it (Stripe metadata, `appAccountToken`, `obfuscatedExternalAccountId`); dawl never interprets it.

## Development

```bash
golangci-lint run && go test -race ./...
```

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are accepted under the [Contributor License Agreement](CONTRIBUTOR_LICENSE_AGREEMENT.md).

## License

dawl is released under the [MIT License](LICENSE).
