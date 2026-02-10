# Expert API

A cloud-native e-commerce REST API built with Python and Flask, deployed on Google Cloud Functions. It provides a complete backend for managing customers, products, shopping carts, wishlists, and notifications — powered by Firestore and Google Cloud Storage.

## Tech Stack

- **Runtime:** Python (Flask) on Google Cloud Functions
- **Database:** Cloud Firestore (NoSQL)
- **Storage:** Google Cloud Storage (product images)
- **Auth:** JWT-based authentication with role-based access control
- **Other:** Pillow (image processing), Pandas (batch uploads via CSV/Excel)

## Features

- **Authentication** — Sign up, login, and JWT token management with password hashing
- **Role-Based Access Control** — Admin, sub-admin, and customer roles with endpoint-level permissions
- **Product Management** — Full CRUD with image uploads, category/subcategory organization, search, and filtering
- **Batch Product Upload** — Bulk import products from Excel/CSV files with Google Drive image support
- **Shopping Cart** — Add, update quantity, remove items, and clear cart
- **Wishlist** — Save products, remove them, or move directly to cart
- **Checkout & Orders** — Multi-step checkout flow with order lifecycle (quoted → confirmed → delivered → paid)
- **Delivery** — Set delivery addresses on orders from address book or manual entry, admin delivery confirmation
- **Payments** — Admin-confirmed payments with a 30-day payment window
- **Quotes** — Request quotes for non-catalog items with admin response tracking
- **Address Management** — Multiple delivery addresses per user with default address handling
- **Notifications** — Admin-driven notification system with read/unread tracking
- **Image Handling** — Multi-image upload per product (JPG/PNG), stored in GCS with public URLs

## API Endpoints

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/signup` | Create a new customer account |
| POST | `/login` | Authenticate and receive a JWT token |

### Products
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/create-product` | Create a product with image upload |
| GET | `/get-product` | Get a single product by ID |
| GET | `/get-all-products` | List products (with category filter & search) |
| DELETE | `/delete-product` | Delete a product and its images |
| POST | `/add-product-images` | Upload additional images to a product |
| DELETE | `/delete-product-image` | Remove specific product images |
| POST | `/batch-product-upload` | Bulk upload products via Excel/CSV |

### Categories
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/add-category` | Create a category |
| GET | `/list-categories` | List all categories with subcategories |
| PUT | `/edit-category` | Update a category |
| DELETE | `/delete-category` | Remove a category |

### Subcategories
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/add-subcategory` | Add a subcategory to a category |
| GET | `/list-subcategories` | List subcategories for a category |
| PUT | `/edit-subcategory` | Update a subcategory |
| DELETE | `/delete-subcategory` | Remove a subcategory |

### Cart
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/get-cart-items` | List all items in the cart |
| POST | `/add-to-cart` | Add a product to the cart |
| PUT | `/update-cart-quantity` | Update item quantity |
| DELETE | `/delete-from-cart` | Remove an item from the cart |
| DELETE | `/clear-cart` | Empty the entire cart |

### Wishlist
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/add-to-wishlist` | Save a product to the wishlist |
| DELETE | `/delete-from-wishlist` | Remove a product from the wishlist |
| DELETE | `/clear-wishlist` | Clear the entire wishlist |
| POST | `/move-from-wishlist-to-cart` | Move an item from wishlist to cart |

### Checkout
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/checkout-items` | Move selected cart items to checkout staging |
| POST | `/move-checkout-to-cart` | Move checkout items back to cart |
| POST | `/process-checkout` | Create an order from checkout items |

### Orders
| Method | Endpoint | Description |
|--------|----------|-------------|
| PUT | `/confirm-order` | Confirm a quoted order |
| PUT | `/cancel-order` | Cancel a quoted or confirmed order |
| PUT | `/set-order-address` | Set delivery address on an order |
| PUT | `/confirm-delivery` | Mark an order as delivered (admin) |
| PUT | `/confirm-payment` | Mark an order as paid (admin) |

### Quotes
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/get-quote` | Request a quote for a non-cart item |

### Addresses
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/add-address` | Add a delivery address |
| PUT | `/edit-address` | Update an existing address |
| GET | `/list-addresses` | List all addresses for the user |
| DELETE | `/delete-address` | Remove an address |

### Notifications
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/add-notification` | Send notifications to users (admin) |
| GET | `/list-notifications` | List notifications for a user |
| PUT | `/mark-notification-read` | Mark a notification as read |

## Architecture

```
Client Request
    │
    ▼
Google Cloud Function (HTTP trigger)
    │
    ▼
Flask Router ──► JWT Auth Middleware ──► Role Check
    │
    ├──► Firestore (users, products, categories, carts, wishlists, orders, quotes)
    └──► Cloud Storage (product images)
```

**Data Model:**
- `customers` — user profiles with subcollections for addresses, notifications, cart, checkout, and wishlist
- `products` — product catalog with images stored in GCS
- `categories` — hierarchical categories with subcategories
- `orders` — order records with items, subtotal, status, delivery address, and payment due date
- `quotes` — quote requests for non-catalog items with admin response tracking

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Set the JWT secret
export expert_secret="your-secret-key"

# Run locally
functions-framework --target=app --debug

# Deploy to GCP
gcloud functions deploy app --runtime python39 --trigger-http --allow-unauthenticated
```

## Auth

All protected endpoints require a JWT token in the `Authorization` header:

```
Authorization: Bearer <token>
```

Tokens are issued on login and expire after 7 days.

## License

MIT
