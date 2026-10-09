package subscription_test

import (
	"github.com/sourcelocation/dawl/appstore"
	"github.com/sourcelocation/dawl/discord"
	"github.com/sourcelocation/dawl/googleplay"
	"github.com/sourcelocation/dawl/stripe"
	"github.com/sourcelocation/dawl/subscription"
)

// Every store's gateway is a subscription.Gateway.
var (
	_ subscription.Gateway = (*appstore.Gateway)(nil)
	_ subscription.Gateway = (*googleplay.Gateway)(nil)
	_ subscription.Gateway = (*stripe.Gateway)(nil)
	_ subscription.Gateway = (*discord.Gateway)(nil)

	_ subscription.Renewer = (*stripe.Gateway)(nil)
	_ subscription.Catalog = (*stripe.Gateway)(nil)
)
