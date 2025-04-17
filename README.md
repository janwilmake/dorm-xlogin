This is a template (under 5k tokens in size), made from first principles, for:

- Secure login via X OAuth
- User managment via dorm (powered by [outerbase](https://outerbase.com))
- Stripe payment processing (powered by [stripeflare](https://github.com/janwilmake/stripeflare))

Use this boilerplate fore easy creation of apps with subscribers or features behind one-time payment.

To use this:

- make a client at https://developer.x.com
- make sure to provide the right "User authentication settings", specifically the callback URLs should include https://your-worker.com/callback
- gather all vars in both .dev.vars and wrangler.jsonc, and in your deployed secrets. for stripe instructions, see https://github.com/janwilmake/stripeflare
- To explore the data in the DB: https://studio.outerbase.com/local/new-base/starbase and fill https://login.xymake.com/admin

[Find me on X](https://x.com/janwilmake)

TODO:

- Add logic to generate payment-link bound to the user for correct user matching. Now this is a great boilerplate that allows easy creation of apps with subscribers or features behind one-time payment.
