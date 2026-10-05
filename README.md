# dawl

Subscriptions from every store, in one vocabulary. dawl verifies what Stripe, the App Store and Google Play report about a subscription and normalises it into a single `subscription.State`, with one rule for whether it grants access right now.

It is the store-facing half of billing, shared by [Rondo](https://github.com/sourcelocation/rondo) and [Invaris](https://github.com/sourcelocation/invaris). Plans, limits, storage and what an app does when a plan changes stay in each app.

| Package | What it does |
| --- | --- |
| [`subscription`](subscription) | `Provider`, `Status`, `State`, `Entitles` and the errors gateways return. Standard library only, so apps can use it from their domain layer. |
| [`stripe`](stripe) | Customers, Checkout, the customer portal, webhook verification, subscription state, cancellation. |
| [`appstore`](appstore) | StoreKit 2 transactions and App Store Server Notifications V2, verified against Apple's root certificate; subscription status from the App Store Server API (production, then sandbox). |
| [`googleplay`](googleplay) | Subscription state and acknowledgement from the Android Publisher API; Real-time Developer Notifications verified from their Pub/Sub push. |

```go
gw := stripe.New(stripe.Config{SecretKey: key, WebhookSecret: whsec, AccountMetadataKey: "app_account"})

hook, err := gw.ParseWebhook(body, r.Header.Get("Stripe-Signature"))
switch {
case errors.Is(err, subscription.ErrInvalidNotification):
	// 401: not from Stripe
case err != nil:
	// 400 or 500
case hook.Subscription != nil:
	save(hook.Subscription.Account, *hook.Subscription) // then: hook.Subscription.Entitles(time.Now())
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

dawl is free software under the [GNU Affero General Public License v3.0](LICENSE).
