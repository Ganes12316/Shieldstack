import stripe

# Stripe PUBLISHABLE keys (prefix pk_) are designed to be exposed client-side —
# only SECRET keys (prefix sk_) need protection. This is the actual Stripe test
# publishable key from their own public documentation.
API_KEY = "pk_test_TYooMQauvdEDq54NiTphI7jx"
stripe.api_key = API_KEY
