# Auth

## Register

- Hash password - bcrypt
- Create user
- Send verification email - TODO Later
- Verify user - TODO Later
- Generate JWT
- Set cookie
- Send response

## Login

- Check if user exists
- Check if password matches - bcrypt
- Generate JWT
- Set cookie
- Send response

## Logout

- Delete cookie
- Send response

## Is Authenticated - In middleware, check if user is authenticated

- Get token from cookie
- Verify token
- Set req.user
- Call next() to move to the next middleware or route handler
