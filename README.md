# Protect your Rust + Actix Web API with Unkey

This example shows how to secure a Rust + Actix Web API using Unkey for API key management. You'll learn how to protect public and private routes with minimal setup and start authenticating users quickly.

## Quick Start

### Create a root key

1. Go to /settings/root-keys and click on the "Create New Root Key" button.
2. Enter a name for the key.
3. Select the following workspace permissions: create_key, read_key, encrypt_key and decrypt_key.
4. Click "Create".

### Create your API

1. Go to https://app.unkey.com/apis and click on the "Create New API" button.
2. Give it a name.
3. Click "Create".

### Create your first API key

1. Click "Create Key" in the top right corner.
2. Feel the form with any key information you want or leave it empty.
3. Click "Create"
4. Copy the key and save it somewhere safe.

### Set up the example

1. Clone the repository to your local machine.

```bash

git clone <repo-url>
cd /path/to/repo

```

2. Duplicate the `.env.example` file and rename it to `.env`.

```bash

cp .env.example .env

```

3. Replace your API key in the `.env` file.

4. Start the server.

```bash

cargo run

```

5. Test the public route as a guest:
```bash

curl http://localhost:3000/public

```

6. Test the public route as an authorized user by passing the API key in the header:

```bash

curl http://localhost:3000/public -H "Authorization: Bearer <YOUR_API_KEY>"

```

7. Test the protected route, which requires valid authorization:

```bash

curl http://localhost:3000/protected -H "Authorization: Bearer <YOUR_API_KEY>"

```
