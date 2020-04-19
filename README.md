<p align="center">
  <a href="https://github.com/davideasaf/fast-legion"><img src="https://i.imgur.com/5TnV0Ci.png" alt="Fast-Legion"></a>
</p>
<p align="center">
    <em>A JWT Security Bundle that let's you choose your favorite data layer for the FastAPI framework.</em>
</p>

## Key features:

- **Fast First**: Fast Legion was built with FastAPI in mind first. That means typing, DI, docs, and flexibilty are key.
- **Simple to Integrate**: Provide a Config and some function wrappers around your data layer and you've got a modern JWT secure API.
- **Zero Favorites**: FastAPI doesn't pick favorites and neither does Fast Legion. Bring your own data layer such as a relational or NoSQL database. As long as you provide users, Fast Legion is happy to secure it.
- **Secure**
  - Hashes passwords and exposes a hashing function for you to use outside of your app
  - Verify plain text passwords against your apps hashed passwords
  - Generate OAuth2.0 compliant authorization tokens on successful user login
  - Set a custom expiration for your tokens
  - Get the full user injected into your route when you need it

## Requirements

Python 3.6+

## Installation

```console
$ pip install fast-legion

---> 100%
```

## Quick Start

Fast legion is setup in 1 step:

```python
from fast_legion import (
    Legion,
    LegionConfig,
)

api = FastAPI(title="Basic API Demo for Fast Legion")

Legion(
    api,
    lookup_by_username=lookup_by_username,
    lookup_by_id=lookup_by_id,
    get_user_rolenames=get_user_rolenames,
    get_user_password_hash=get_user_password_hash,
    get_user_id=get_user_id,
    config=LegionConfig(),
)
```

### Parameters

1. **lookup_by_username**: function to return the user given a username
1. **lookup_by_id**: function to return the user given an id
1. **get_user_rolenames**: function that takes a user and returns list of string usernames
1. **get_user_password_hash**: function that takes a user and returns their hashed password
1. **get_user_id: function**: that takes a user and returns their id
1. **config**: Pydantic Model imported from Fast Legion. Contains all the configurations for Fast Legion (the above shows Fast Legion using all defaults)

for the function signatures, refer to the <a href="https://github.com/davideasaf/fast-legion/tree/master/examples/basic.py" target="_blank">Minimal Example</a>

## Examples

1. <a href="https://github.com/davideasaf/fast-legion/tree/master/examples/basic.py" target="_blank">Minimal Example</a>
2. <a href="https://github.com/davideasaf/fast-legion/tree/master/examples/basic.py" target="_blank">SQLAlchemy Example</a>

## API Docs Output

![Example Docs](https://i.imgur.com/KXKtEsm.png)

## License

This project is licensed under the terms of the MIT license.
