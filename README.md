# JWT TypeORM SQLite Template

Steps to run this project for development:

```bash
# Clone the repository
git clone git@github.com:Acquati/jwt-typeorm-sqlite-template.git

# Open directory
cd jwt-typeorm-sqlite-template

# Copy config file example
cp ./src/config/config.example.ts ./src/config/config.ts

yarn install
yarn start

# Run this migration in the first time setup
yarn run migration:run
```
