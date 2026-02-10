import json
import firebase_admin
from firebase_admin import credentials, firestore
from flask import jsonify, Flask, request
import functions_framework
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import os
import datetime
import uuid
from google.cloud import storage
import traceback
import pandas as pd
import re
import requests


# Initialize Firebase admin once
if not firebase_admin._apps:
    firebase_admin.initialize_app()

db = firestore.client()

SECRET_KEY = os.environ.get("expert_secret")

# Initialize GCS bucket

storage_client = storage.Client()
bucket = storage_client.bucket("expert-images")

# -----------------------------------------
# Helper: create JWT token
# -----------------------------------------
def create_token(user_id, email, role):
    payload = {
        "user_id": user_id,
        "email": email,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


# -----------------------------------------
# Cloud Function main entry
# -----------------------------------------
@functions_framework.http
def app(request):
    request_json = request.get_json(silent=True) or {}
    path = request.path.lower()

    # ---- ROUTES ----
    if path == "/signup":
        return signup(request_json)

    if path == "/login":
        return login(request_json)

    if path == ("/add-address"):
        return add_address(request_json)

    if path == "/edit-address":
        return edit_address(request_json)

    if path == "/list-addresses":
        return list_addresses(request_json)

    if path == "/delete-address":
        return delete_address(request_json)

    if path == "/add-notification":
        return add_notification(request_json)

    if path == "/list-notifications":
        return list_notifications(request_json)

    if path == "/mark-notification-read":
        return mark_notification_read(request_json)

    if path == "/add-category":
        return add_category(request_json)

    if path == "/list-categories":
        return list_categories(request_json)

    if path == "/edit-category":
        return edit_category(request_json)

    if path == "/delete-category":
        return delete_category(request_json)

    if path == "/create-product":
        return create_product(request)
    
    if path == "/get-product":
        return get_product(request, db)

    if path == "/get-all-products":
        return get_all_products(request, db)

    if path == "/delete-product":
        return delete_product(request, db, bucket, SECRET_KEY)

    if path == "/add-product-images":
        return add_product_images(request, db, bucket, SECRET_KEY)

    if path == "/delete-product-image":
        return delete_product_images(request, db, bucket, SECRET_KEY)

    if path == "/batch-product-upload":
        return batch_upload_products(request, db, bucket, SECRET_KEY)

    if path == "/add-to-cart":
        return add_to_cart(request, db, SECRET_KEY)

    if path == "/update-cart-quantity":
        return update_cart_quantity(request, db, SECRET_KEY)

    if path == "/delete-from-cart":
        return delete_from_cart(request, db, SECRET_KEY)

    if path == "/clear-cart":
        return clear_cart(request, db, SECRET_KEY)

    if path == "/add-to-wishlist":
        return add_to_wishlist(request, db, SECRET_KEY)

    if path == "/delete-from-wishlist":
        return delete_from_wishlist(request, db, SECRET_KEY)

    if path == "/clear-wishlist":
        return clear_wishlist(request, db, SECRET_KEY)

    if path == "/move-from-wishlist-to-cart":
        return move_wishlist_to_cart(request, db, SECRET_KEY)

    return jsonify({"error": "Endpoint not found"}), 404


# -----------------------------------------
# SIGNUP ENDPOINT
# -----------------------------------------
def signup(data):
    required = ["first_name", "last_name", "email", "password", "phone"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    email = data["email"].lower().strip()

    # Check if customer already exists
    existing = db.collection("customers").where("email", "==", email).get()
    if existing:
        return jsonify({"error": "Email already exists"}), 409

    user_id = str(uuid.uuid4())
    password_hash = generate_password_hash(data["password"])

    customer_data = {
        "first_name": data["first_name"],
        "last_name": data["last_name"],
        "email": email,
        "password_hash": password_hash,
        "phone": data["phone"],
        "role": "customer",
        "is_active": True,
        "email_verified": False,
        "created_at": firestore.SERVER_TIMESTAMP,
        "updated_at": firestore.SERVER_TIMESTAMP,
        "last_login": None
    }

    db.collection("customers").document(user_id).set(customer_data)

    token = create_token(user_id, email, "customer")

    return jsonify({
        "message": "Signup successful",
        "user_id": user_id,
        "token": token
    }), 201


# -----------------------------------------
# LOGIN ENDPOINT
# -----------------------------------------
def login(data):
    if "email" not in data or "password" not in data:
        return jsonify({"error": "Email and password required"}), 400

    email = data["email"].lower().strip()
    password = data["password"]

    users = db.collection("customers").where("email", "==", email).get()
    if not users:
        return jsonify({"error": "Invalid email or password"}), 401

    user_doc = users[0]
    user = user_doc.to_dict()

    # Check password
    if not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid email or password"}), 401

    # Update last login
    user_doc.reference.update({
        "last_login": firestore.SERVER_TIMESTAMP
    })

    token = create_token(user_doc.id, user["email"], user["role"])

    return jsonify({
        "message": "Login successful",
        "user_id": user_doc.id,
        "token": token
    }), 200


# -----------------------------------------
# ADD ADDRESS USING JWT TOKEN (CUSTOM FIELDS)
# -----------------------------------------
def add_address(data):
    # Get Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token required"}), 401

    token = auth_header.split(" ")[1]

    # Decode JWT token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("user_id")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    # Required fields
    required = ["address_line1", "city", "country", "region"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    # Optional fields
    address_line2 = data.get("address_line2", "")
    delivery_instructions = data.get("delivery_instructions", "")
    is_default_str = data.get("is_default")
    is_default = str(is_default_str).lower() == "true" if is_default_str is not None else None

    # Check if user exists
    user_ref = db.collection("customers").document(user_id)
    user_doc = user_ref.get()
    if not user_doc.exists:
        return jsonify({"error": "User not found"}), 404

    addresses_ref = user_ref.collection("addresses")

    # If is_default is True, unset all other defaults
    if is_default:
        default_addresses = addresses_ref.where("is_default", "==", True).get()
        for addr in default_addresses:
            addr.reference.update({"is_default": False})
    # If is_default is None, don't change default status
    else:
        is_default = False

    # Generate new address ID
    address_id = str(uuid.uuid4())

    address_data = {
        "address_line1": data["address_line1"],
        "address_line2": address_line2,
        "city": data["city"],
        "country": data["country"],
        "region": data["region"],
        "delivery_instructions": delivery_instructions,
        "is_default": is_default,
        "created_at": firestore.SERVER_TIMESTAMP,
        "updated_at": firestore.SERVER_TIMESTAMP
    }

    # Save new address
    addresses_ref.document(address_id).set(address_data)

    return jsonify({
        "message": "Address added successfully",
        "address_id": address_id
    }), 201


# -----------------------------------------
# EDIT ADDRESS USING JWT TOKEN (CUSTOM FIELDS, ALL OPTIONAL)
# -----------------------------------------
def edit_address(data):
    # Get Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token required"}), 401

    token = auth_header.split(" ")[1]

    # Decode JWT token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("user_id")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    address_id = data.get("address_id")
    if not address_id:
        return jsonify({"error": "Missing field: address_id"}), 400

    user_ref = db.collection("customers").document(user_id)
    address_ref = user_ref.collection("addresses").document(address_id)

    address_doc = address_ref.get()
    if not address_doc.exists:
        return jsonify({"error": "Address not found"}), 404

    # Optional fields to update
    update_data = {}
    optional_fields = ["address_line1", "address_line2", "city", "country", "region", "delivery_instructions"]
    for field in optional_fields:
        if field in data:
            update_data[field] = data[field]

    # Handle is_default separately
    if "is_default" in data:
        is_default = str(data["is_default"]).lower() == "true"
        if is_default:
            # Unset all other default addresses
            default_addresses = user_ref.collection("addresses").where("is_default", "==", True).get()
            for addr in default_addresses:
                addr.reference.update({"is_default": False})
        update_data["is_default"] = is_default

    # Always update updated_at timestamp
    update_data["updated_at"] = firestore.SERVER_TIMESTAMP

    address_ref.update(update_data)

    return jsonify({
        "message": "Address updated successfully",
        "address_id": address_id
    }), 200


# -----------------------------------------
# LIST ADDRESSES USING JWT TOKEN
# -----------------------------------------
def list_addresses(_):
    # Get Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token required"}), 401

    token = auth_header.split(" ")[1]

    # Decode JWT token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("user_id")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    user_ref = db.collection("customers").document(user_id)
    user_doc = user_ref.get()
    if not user_doc.exists:
        return jsonify({"error": "User not found"}), 404

    addresses_ref = user_ref.collection("addresses")
    addresses_docs = addresses_ref.get()

    addresses = []
    for doc in addresses_docs:
        addr = doc.to_dict()
        addr["address_id"] = doc.id
        addresses.append(addr)

    return jsonify({"addresses": addresses}), 200


# -----------------------------------------
# DELETE ADDRESS USING JWT TOKEN (WITH DEFAULT HANDLING)
# -----------------------------------------
def delete_address(data):
    # Get Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token required"}), 401

    token = auth_header.split(" ")[1]

    # Decode JWT token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("user_id")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    address_id = data.get("address_id")
    if not address_id:
        return jsonify({"error": "Missing field: address_id"}), 400

    user_ref = db.collection("customers").document(user_id)
    address_ref = user_ref.collection("addresses").document(address_id)

    address_doc = address_ref.get()
    if not address_doc.exists:
        return jsonify({"error": "Address not found"}), 404

    # Check if the address is default
    address_data = address_doc.to_dict()
    was_default = address_data.get("is_default", False)

    # Delete the address
    address_ref.delete()

    # If deleted address was default, assign a new default if there are other addresses
    if was_default:
        remaining_addresses = user_ref.collection("addresses").get()
        if remaining_addresses:
            # Pick the first remaining address and set as default
            new_default = remaining_addresses[0]
            new_default.reference.update({
                "is_default": True,
                "updated_at": firestore.SERVER_TIMESTAMP
            })

    return jsonify({
        "message": "Address deleted successfully",
        "address_id": address_id
    }), 200


# -----------------------------------------
# LIST NOTIFICATIONS USING JWT TOKEN
# -----------------------------------------
def list_notifications(_):
    # Get Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token required"}), 401

    token = auth_header.split(" ")[1]

    # Decode JWT token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("user_id")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    user_ref = db.collection("customers").document(user_id)
    user_doc = user_ref.get()
    if not user_doc.exists:
        return jsonify({"error": "User not found"}), 404

    notifications_ref = user_ref.collection("notifications").order_by("created_at", direction=firestore.Query.DESCENDING)
    notifications_docs = notifications_ref.get()

    notifications = []
    for doc in notifications_docs:
        notif = doc.to_dict()
        notif["notification_id"] = doc.id
        notifications.append(notif)

    return jsonify({"notifications": notifications}), 200


# -----------------------------------------
# ADD NOTIFICATION USING JWT TOKEN (ADMIN ONLY, MULTIPLE USERS)
# -----------------------------------------
def add_notification(data):
    # Get Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token required"}), 401

    token = auth_header.split(" ")[1]

    # Decode JWT token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        role = payload.get("role")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    # Only admins can send notifications
    if role not in ["admin", "sub-admin", "super-admin"]:
        return jsonify({"error": "Only admins can send notifications"}), 403

    # Required fields
    required = ["title", "message", "type", "reference_type", "reference_id", "user_ids"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    user_ids = data["user_ids"]
    if not isinstance(user_ids, list) or not user_ids:
        return jsonify({"error": "user_ids must be a non-empty list"}), 400

    added_notifications = []

    # Loop through each user_id and create a notification
    for target_user_id in user_ids:
        user_ref = db.collection("customers").document(target_user_id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            continue  # Skip invalid users

        notification_id = str(uuid.uuid4())
        notification_data = {
            "title": data["title"],
            "message": data["message"],
            "type": data["type"],
            "reference_type": data["reference_type"],
            "reference_id": data["reference_id"],
            "is_read": False,
            "created_at": firestore.SERVER_TIMESTAMP
        }

        user_ref.collection("notifications").document(notification_id).set(notification_data)
        added_notifications.append({"user_id": target_user_id, "notification_id": notification_id})

    return jsonify({
        "message": "Notifications added successfully",
        "notifications": added_notifications
    }), 201


# -----------------------------------------
# MARK NOTIFICATION AS READ USING JWT TOKEN
# -----------------------------------------
def mark_notification_read(data):
    # Get Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token required"}), 401

    token = auth_header.split(" ")[1]

    # Decode JWT token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("user_id")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    notification_id = data.get("notification_id")
    if not notification_id:
        return jsonify({"error": "Missing field: notification_id"}), 400

    user_ref = db.collection("customers").document(user_id)
    notif_ref = user_ref.collection("notifications").document(notification_id)

    notif_doc = notif_ref.get()
    if not notif_doc.exists:
        return jsonify({"error": "Notification not found"}), 404

    notif_ref.update({
        "is_read": True
    })

    return jsonify({
        "message": "Notification marked as read",
        "notification_id": notification_id
    }), 200


# -----------------------------------------
# ADD CATEGORY OR SUBCATEGORY (ADMIN ONLY)
# -----------------------------------------
def add_category(data):
    # Get Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token required"}), 401

    token = auth_header.split(" ")[1]

    # Decode JWT token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        role = payload.get("role")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    if role not in ["admin", "sub-admin", "super-admin"]:
        return jsonify({"error": "Only admins can manage categories"}), 403

    # Required fields
    if "name" not in data:
        return jsonify({"error": "Missing field: name"}), 400

    name = data["name"]
    description = data.get("description", "")
    parent_id = data.get("parent_id")  # Optional: if adding a subcategory

    category_id = str(uuid.uuid4())
    category_data = {
        "name": name,
        "description": description,
        "created_at": firestore.SERVER_TIMESTAMP,
        "updated_at": firestore.SERVER_TIMESTAMP
    }

    if parent_id:
        # Add as subcategory under parent
        parent_ref = db.collection("categories").document(parent_id)
        if not parent_ref.get().exists:
            return jsonify({"error": "Parent category not found"}), 404
        parent_ref.collection("subcategories").document(category_id).set(category_data)
    else:
        # Add as main category
        db.collection("categories").document(category_id).set(category_data)

    return jsonify({
        "message": "Category added successfully",
        "category_id": category_id,
        "parent_id": parent_id
    }), 201


# -----------------------------------------
# VIEW ALL CATEGORIES (ALL USERS)
# -----------------------------------------
def list_categories(_):
    # Get Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token required"}), 401

    token = auth_header.split(" ")[1]

    # Decode JWT token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("user_id")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    # Optional: check if user exists
    user_ref = db.collection("customers").document(user_id)
    if not user_ref.get().exists:
        return jsonify({"error": "User not found"}), 404

    categories_ref = db.collection("categories")
    categories_docs = categories_ref.get()

    categories = []
    for doc in categories_docs:
        category = doc.to_dict()
        category["category_id"] = doc.id

        # Get subcategories
        sub_docs = doc.reference.collection("subcategories").get()
        subcategories = []
        for sub in sub_docs:
            sub_data = sub.to_dict()
            sub_data["subcategory_id"] = sub.id
            subcategories.append(sub_data)

        category["subcategories"] = subcategories
        categories.append(category)

    return jsonify({"categories": categories}), 200
    

# -----------------------------------------
# EDIT CATEGORY OR SUBCATEGORY (ADMIN ONLY)
# -----------------------------------------
def edit_category(data):
    # Get Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token required"}), 401

    token = auth_header.split(" ")[1]

    # Decode JWT token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        role = payload.get("role")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    if role not in ["admin", "sub-admin", "super-admin"]:
        return jsonify({"error": "Only admins can edit categories"}), 403

    category_id = data.get("category_id")
    if not category_id:
        return jsonify({"error": "Missing field: category_id"}), 400

    parent_id = data.get("parent_id")  # Optional if editing a subcategory
    update_data = {}
    if "name" in data:
        update_data["name"] = data["name"]
    if "description" in data:
        update_data["description"] = data["description"]

    if not update_data:
        return jsonify({"error": "No fields to update"}), 400

    update_data["updated_at"] = firestore.SERVER_TIMESTAMP

    if parent_id:
        # Editing a subcategory
        category_ref = db.collection("categories").document(parent_id).collection("subcategories").document(category_id)
    else:
        # Editing a main category
        category_ref = db.collection("categories").document(category_id)

    if not category_ref.get().exists:
        return jsonify({"error": "Category not found"}), 404

    category_ref.update(update_data)

    return jsonify({"message": "Category updated successfully"}), 200


# -----------------------------------------
# DELETE CATEGORY OR SUBCATEGORY (ADMIN ONLY)
# -----------------------------------------
def delete_category(data):
    # Get Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token required"}), 401

    token = auth_header.split(" ")[1]

    # Decode JWT token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        role = payload.get("role")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    if role not in ["admin", "sub-admin", "super-admin"]:
        return jsonify({"error": "Only admins can delete categories"}), 403

    category_id = data.get("category_id")
    if not category_id:
        return jsonify({"error": "Missing field: category_id"}), 400

    parent_id = data.get("parent_id")  # Optional for subcategory

    if parent_id:
        category_ref = db.collection("categories").document(parent_id).collection("subcategories").document(category_id)
    else:
        category_ref = db.collection("categories").document(category_id)

    if not category_ref.get().exists:
        return jsonify({"error": "Category not found"}), 404

    # Delete the category/subcategory
    category_ref.delete()

    return jsonify({"message": "Category deleted successfully"}), 200


# -----------------------------------------
# CREATE SINGLE PRODUCT (SKU + IMAGE FILE UPLOAD)
# -----------------------------------------
def create_product(request):

    try:
        # -------------------------
        # JWT AUTH
        # -------------------------
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            print("AUTH ERROR: Missing Authorization header")
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            role = payload.get("role")
        except jwt.ExpiredSignatureError:
            print("AUTH ERROR: Token expired")
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            print("AUTH ERROR: Invalid token")
            return jsonify({"error": "Invalid token"}), 401

        if role not in ["admin", "sub-admin", "super-admin"]:
            print(f"AUTH ERROR: Unauthorized role {role}")
            return jsonify({"error": "Unauthorized"}), 403

        # -------------------------
        # FORM DATA
        # -------------------------
        if not request.content_type.startswith("multipart/form-data"):
            print("FORM ERROR: Wrong Content-Type:", request.content_type)
            return jsonify({"error": "Content-Type must be multipart/form-data"}), 415

        # Required text fields
        name = request.form.get("name")
        sku = request.form.get("sku")
        category_name = request.form.get("category_name")  # exact match
        subcategory_name = request.form.get("subcategory_name")  # exact match
        brand = request.form.get("brand")
        color = request.form.get("color")
        description = request.form.get("description")
        dimensions = request.form.get("dimensions")
        price = request.form.get("price")
        stock = request.form.get("stock")

        required = [name, sku, category_name, subcategory_name, price]
        if any(not field for field in required):
            print("FORM ERROR: Missing required fields")
            return jsonify({"error": "Missing required fields"}), 400

        try:
            price = float(price)
            stock = int(stock) if stock else 0
        except ValueError:
            print("FORM ERROR: Invalid price or stock")
            return jsonify({"error": "Price must be number, stock must be integer"}), 400

        # -------------------------
        # SKU uniqueness
        # -------------------------
        sku_check = db.collection("products").where("sku", "==", sku).limit(1).get()
        if sku_check:
            print(f"SKU ERROR: SKU {sku} already exists")
            return jsonify({"error": "SKU already exists"}), 409

        # -------------------------
        # Category & Subcategory lookup (exact match)
        # -------------------------
        cat_query = db.collection("categories").where("name", "==", category_name).get()
        if not cat_query:
            print(f"CATEGORY ERROR: Category {category_name} not found")
            return jsonify({"error": "Category not found"}), 404
        category_id = cat_query[0].id

        sub_query = db.collection("categories").document(category_id)\
            .collection("subcategories").where("name", "==", subcategory_name).get()
        if not sub_query:
            print(f"SUBCATEGORY ERROR: Subcategory {subcategory_name} not found")
            return jsonify({"error": "Subcategory not found"}), 404
        subcategory_id = sub_query[0].id

        # -------------------------
        # Product ID & Images
        # -------------------------
        product_id = str(uuid.uuid4())
        image_urls = []
        uploaded_files = request.files.getlist("images")

        if not uploaded_files:
            print("IMAGE ERROR: No images uploaded")
            return jsonify({"error": "At least one image is required"}), 400

        allowed_extensions = ["jpg", "jpeg", "png"]
        safe_name = name.replace(" ", "_")
        seq = 1

        for file in uploaded_files:
            ext = file.filename.split(".")[-1].lower()
            if ext not in allowed_extensions:
                print(f"IMAGE ERROR: Invalid file extension {ext}")
                return jsonify({"error": f"Invalid file extension: {ext}"}), 400

            try:
                filename = f"{safe_name}_{str(seq).zfill(3)}.{ext}"
                blob = bucket.blob(f"products/{product_id}/{filename}")

                # Upload image
                blob.upload_from_file(file, content_type=file.content_type)

                # With uniform bucket-level access, just use public_url
                image_urls.append(blob.public_url)
                seq += 1
            except Exception as e:
                print("BUCKET ERROR:", str(e))
                print(traceback.format_exc())
                return jsonify({"error": "Failed to upload image"}), 500

        # -------------------------
        # Save Product in Firestore
        # -------------------------
        try:
            product_data = {
                "name": name,
                "sku": sku,
                "category_id": category_id,
                "subcategory_id": subcategory_id,
                "brand": brand,
                "color": color,
                "description": description,
                "dimensions": dimensions,
                "price": price,
                "stock": stock,
                "images": image_urls,
                "created_at": firestore.SERVER_TIMESTAMP,
                "updated_at": firestore.SERVER_TIMESTAMP
            }

            db.collection("products").document(product_id).set(product_data)
        except Exception as e:
            print("FIRESTORE ERROR:", str(e))
            print(traceback.format_exc())
            return jsonify({"error": "Failed to save product"}), 500

        return jsonify({
            "message": "Product created successfully",
            "product_id": product_id,
            "sku": sku,
            "images_uploaded": len(image_urls)
        }), 201

    except Exception as e:
        print("UNEXPECTED ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

# -----------------------------------------
# GET SINGLE PRODUCT (PUBLIC)
# -----------------------------------------
def get_product(request, db):
    try:
        # Get product_id from query params
        product_id = request.args.get("product_id")
        if not product_id:
            return jsonify({"error": "Missing product_id parameter"}), 400

        # Fetch product
        product_doc = db.collection("products").document(product_id).get()
        if not product_doc.exists:
            return jsonify({"error": "Product not found"}), 404

        product = product_doc.to_dict()
        product["id"] = product_doc.id

        return jsonify({"product": product}), 200

    except Exception as e:
        print("UNEXPECTED ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

# -----------------------------------------
# GET ALL PRODUCTS (PUBLIC)
# -----------------------------------------
def get_all_products(request, db):
    try:
        products_ref = db.collection("products")

        # Optional query parameters
        category_id = request.args.get("category_id")
        search = request.args.get("search")

        query = products_ref

        if category_id:
            query = query.where("category_id", "==", category_id)

        products_docs = query.stream()

        products = []
        for doc in products_docs:
            product = doc.to_dict()
            product["id"] = doc.id
            if search:
                if search.lower() not in product.get("name", "").lower():
                    continue
            products.append(product)

        return jsonify({"products": products, "count": len(products)}), 200

    except Exception as e:
        print("UNEXPECTED ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# DELETE PRODUCT BY ID
# -----------------------------------------
def delete_product(request, db, bucket, SECRET_KEY):
    try:
        # -------------------------
        # AUTH
        # -------------------------
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        role = payload.get("role")
        if role not in ["admin", "sub-admin", "super-admin"]:
            return jsonify({"error": "Unauthorized"}), 403

        # -------------------------
        # INPUT
        # -------------------------
        product_id = request.args.get("product_id")
        if not product_id:
            return jsonify({"error": "Missing product_id parameter"}), 400

        # -------------------------
        # FETCH PRODUCT
        # -------------------------
        product_ref = db.collection("products").document(product_id)
        product_doc = product_ref.get()

        if not product_doc.exists:
            return jsonify({"error": "Product not found"}), 404

        # -------------------------
        # DELETE IMAGES (ENTIRE FOLDER)
        # -------------------------
        folder_prefix = f"products/{product_id}/"

        try:
            blobs = bucket.list_blobs(prefix=folder_prefix)
            deleted_count = 0

            for blob in blobs:
                blob.delete()
                deleted_count += 1

            print(f"Deleted {deleted_count} image(s) from GCS")

        except Exception as img_err:
            print("IMAGE DELETE ERROR:", str(img_err))
            print(traceback.format_exc())
            return jsonify({"error": "Failed to delete product images"}), 500

        # -------------------------
        # DELETE PRODUCT DOC
        # -------------------------
        product_ref.delete()

        return jsonify({
            "message": "Product deleted successfully",
            "product_id": product_id
        }), 200

    except Exception as e:
        print("UNEXPECTED ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500



# -----------------------------------------
# EDIT PRODUCT (Non-Image)
# -----------------------------------------
def edit_product(request):
    try:
        # -------------------------
        # AUTH
        # -------------------------
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            role = payload.get("role")
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        if role not in ["admin", "sub-admin", "super-admin"]:
            return jsonify({"error": "Unauthorized"}), 403

        # -------------------------
        # INPUT (JSON ONLY)
        # -------------------------
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "JSON body required"}), 400

        product_id = data.get("product_id")
        if not product_id:
            return jsonify({"error": "product_id is required"}), 400

        # -------------------------
        # FETCH PRODUCT
        # -------------------------
        product_ref = db.collection("products").document(product_id)
        product_doc = product_ref.get()

        if not product_doc.exists:
            return jsonify({"error": "Product not found"}), 404

        # -------------------------
        # FIELDS ALLOWED TO UPDATE
        # -------------------------
        allowed_fields = [
            "name",
            "category_id",
            "subcategory_id",
            "brand",
            "color",
            "description",
            "dimensions",
            "price",
            "stock"
        ]

        update_data = {}

        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]

        # Prevent empty update
        if not update_data:
            return jsonify({"error": "No valid fields provided"}), 400

        # Type safety
        if "price" in update_data:
            try:
                update_data["price"] = float(update_data["price"])
            except ValueError:
                return jsonify({"error": "Invalid price"}), 400

        if "stock" in update_data:
            try:
                update_data["stock"] = int(update_data["stock"])
            except ValueError:
                return jsonify({"error": "Invalid stock"}), 400

        # Always update timestamp
        update_data["updated_at"] = firestore.SERVER_TIMESTAMP

        # -------------------------
        # UPDATE FIRESTORE
        # -------------------------
        product_ref.update(update_data)

        return jsonify({
            "message": "Product updated successfully",
            "product_id": product_id,
            "updated_fields": list(update_data.keys())
        }), 200

    except Exception as e:
        print("EDIT PRODUCT ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# EDIT PRODUCT (Delete Image)
# -----------------------------------------
def delete_product_images(request, db, bucket, SECRET_KEY):
    try:
        # -------------------------
        # AUTH
        # -------------------------
        auth_header = request.headers.get("Authorization")
        print("Auth header received:", auth_header)

        if not auth_header or not auth_header.startswith("Bearer "):
            print("Missing or invalid Authorization header")
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]
        print("Token extracted:", token)

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            role = payload.get("role")
            print("Decoded payload:", payload)
        except jwt.ExpiredSignatureError:
            print("Token expired")
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            print("Invalid token")
            return jsonify({"error": "Invalid token"}), 401

        if role not in ["admin", "sub-admin", "super-admin"]:
            print("Unauthorized role:", role)
            return jsonify({"error": "Unauthorized"}), 403

        # -------------------------
        # BODY
        # -------------------------
        data = request.get_json(silent=True)
        print("Request body:", data)

        if not data:
            return jsonify({"error": "JSON body required"}), 400

        product_id = data.get("product_id")
        image_urls = data.get("image_urls", [])

        if not product_id or not image_urls:
            return jsonify({
                "error": "product_id and image_urls are required"
            }), 400

        # -------------------------
        # FETCH PRODUCT
        # -------------------------
        product_ref = db.collection("products").document(product_id)
        product_doc = product_ref.get()

        if not product_doc.exists:
            print("Product not found:", product_id)
            return jsonify({"error": "Product not found"}), 404

        product = product_doc.to_dict()
        current_images = product.get("images", [])

        deleted = []
        failed = []

        # -------------------------
        # DELETE IMAGES
        # -------------------------
        for url in image_urls:
            if url not in current_images:
                print("URL not found in product images:", url)
                failed.append(url)
                continue

            try:
                # Convert public URL → blob path
                # https://storage.googleapis.com/bucket-name/path/to/file
                prefix = f"https://storage.googleapis.com/{bucket.name}/"
                if not url.startswith(prefix):
                    print("Invalid image URL format:", url)
                    failed.append(url)
                    continue

                blob_path = url.replace(prefix, "")
                print("Deleting blob:", blob_path)

                blob = bucket.blob(blob_path)
                blob.delete()

                current_images.remove(url)
                deleted.append(url)

            except Exception as e:
                print("IMAGE DELETE ERROR:", e)
                failed.append(url)

        # -------------------------
        # UPDATE FIRESTORE
        # -------------------------
        product_ref.update({
            "images": current_images,
            "updated_at": firestore.SERVER_TIMESTAMP
        })

        print(f"Images deleted: {len(deleted)}, remaining: {len(current_images)}")

        return jsonify({
            "message": "Image deletion completed",
            "product_id": product_id,
            "deleted_images": deleted,
            "failed_images": failed,
            "remaining_images": len(current_images)
        }), 200

    except Exception as e:
        print("DELETE IMAGE ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# EDIT PRODUCT (Add Image)
# -----------------------------------------
def add_product_images(request, db, bucket, SECRET_KEY):
    try:
        # ---- AUTH ----
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        role = payload.get("role")
        if role not in ["admin", "sub-admin", "super-admin"]:
            return jsonify({"error": "Unauthorized"}), 403

        # ---- FORM DATA ----
        if not request.content_type.startswith("multipart/form-data"):
            return jsonify({"error": "Content-Type must be multipart/form-data"}), 415

        product_id = request.form.get("product_id")
        if not product_id:
            return jsonify({"error": "Missing product_id"}), 400

        # Get reference and snapshot separately
        product_ref = db.collection("products").document(product_id)
        product_doc = product_ref.get()

        if not product_doc.exists:
            return jsonify({"error": "Product not found"}), 404

        product = product_doc.to_dict()
        current_images = product.get("images", [])

        uploaded_files = request.files.getlist("images")
        if not uploaded_files:
            return jsonify({"error": "No images provided"}), 400

        allowed_extensions = ["jpg", "jpeg", "png"]
        seq = len(current_images) + 1
        safe_name = product.get("name", "product").replace(" ", "_")
        new_image_urls = []

        for file in uploaded_files:
            ext = file.filename.split(".")[-1].lower()
            if ext not in allowed_extensions:
                return jsonify({"error": f"Invalid file extension: {ext}"}), 400

            filename = f"{safe_name}_{str(seq).zfill(3)}.{ext}"
            blob = bucket.blob(f"products/{product_id}/{filename}")
            blob.upload_from_file(file, content_type=file.content_type)
            new_image_urls.append(blob.public_url)
            seq += 1

        # ---- UPDATE FIRESTORE ----
        updated_images = current_images + new_image_urls
        product_ref.update({
            "images": updated_images,
            "updated_at": firestore.SERVER_TIMESTAMP
        })

        return jsonify({
            "message": "Images added successfully",
            "new_images": new_image_urls,
            "total_images": len(updated_images)
        }), 200

    except Exception as e:
        print("UNEXPECTED ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500



# -----------------------------------------
# BATCH PRODUCT UPLOAD (Excel/CSV + Google Drive Image URLs)
# -----------------------------------------
def batch_upload_products(request, db, bucket, SECRET_KEY):
    try:
        import re
        import requests
        import pandas as pd
        import uuid
        import traceback
        from flask import jsonify
        from google.cloud import firestore

        # ---- AUTH ----
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        role = payload.get("role")
        if role not in ["admin", "sub-admin", "super-admin"]:
            return jsonify({"error": "Unauthorized"}), 403

        # ---- FILE UPLOAD ----
        if not request.content_type.startswith("multipart/form-data"):
            return jsonify({"error": "Content-Type must be multipart/form-data"}), 415

        uploaded_file = request.files.get("file")
        if not uploaded_file:
            return jsonify({"error": "No file uploaded"}), 400

        # Detect file type
        filename = uploaded_file.filename
        if filename.endswith(".csv"):
            df = pd.read_csv(uploaded_file)
        elif filename.endswith((".xlsx", ".xls")):
            df = pd.read_excel(uploaded_file)
        else:
            return jsonify({"error": "File must be CSV or Excel"}), 400

        required_columns = ["name", "sku", "category_name", "subcategory_name", "price"]
        for col in required_columns:
            if col not in df.columns:
                return jsonify({"error": f"Missing required column: {col}"}), 400

        added_products = []
        errors = []

        for index, row in df.iterrows():
            try:
                name = str(row["name"]).strip()
                sku = str(row["sku"]).strip()
                category_name = str(row["category_name"]).strip()
                subcategory_name = str(row["subcategory_name"]).strip()
                price = float(row["price"])
                stock = int(row["stock"]) if "stock" in row and not pd.isna(row["stock"]) else 0
                brand = str(row["brand"]).strip() if "brand" in row and not pd.isna(row["brand"]) else ""
                color = str(row["color"]).strip() if "color" in row and not pd.isna(row["color"]) else ""
                description = str(row["description"]).strip() if "description" in row and not pd.isna(row["description"]) else ""
                dimensions = str(row["dimensions"]).strip() if "dimensions" in row and not pd.isna(row["dimensions"]) else ""
                
                # Generate product ID now, used for folder
                product_id = str(uuid.uuid4())

                image_urls = []
                if "image_urls" in row and not pd.isna(row["image_urls"]):
                    raw_urls = [url.strip() for url in str(row["image_urls"]).split(",")]
                    safe_name = name.replace(" ", "_")
                    seq = 1

                    for gdrive_url in raw_urls:
                        try:
                            # Extract file ID from Google Drive URL
                            file_id_match = re.search(r"/d/([a-zA-Z0-9_-]+)", gdrive_url)
                            if not file_id_match:
                                file_id_match = re.search(r"id=([a-zA-Z0-9_-]+)", gdrive_url)
                            if not file_id_match:
                                continue
                            file_id = file_id_match.group(1)
                            download_url = f"https://drive.google.com/uc?export=download&id={file_id}"

                            resp = requests.get(download_url, stream=True)
                            if resp.status_code != 200:
                                continue

                            # Determine extension
                            ext = gdrive_url.split(".")[-1].lower()
                            if ext not in ["jpg", "jpeg", "png"]:
                                ext = "jpg"

                            # Sequential filename
                            filename_seq = f"{safe_name}_{str(seq).zfill(3)}.{ext}"
                            blob_name = f"products/{product_id}/{filename_seq}"
                            blob = bucket.blob(blob_name)
                            blob.upload_from_file(resp.raw, content_type=resp.headers.get("Content-Type", "image/jpeg"))

                            image_urls.append(blob.public_url)
                            seq += 1

                        except Exception as img_err:
                            print(f"Failed to process image {gdrive_url}: {img_err}")
                            continue

                # ---- Check SKU uniqueness ----
                if db.collection("products").where("sku", "==", sku).get():
                    errors.append({"row": index + 2, "sku": sku, "error": "SKU already exists"})
                    continue

                # ---- Category & Subcategory lookup ----
                cat_query = db.collection("categories").where("name", "==", category_name).get()
                if not cat_query:
                    errors.append({"row": index + 2, "sku": sku, "error": f"Category '{category_name}' not found"})
                    continue
                category_id = cat_query[0].id

                sub_query = db.collection("categories").document(category_id)\
                    .collection("subcategories").where("name", "==", subcategory_name).get()
                if not sub_query:
                    errors.append({"row": index + 2, "sku": sku, "error": f"Subcategory '{subcategory_name}' not found"})
                    continue
                subcategory_id = sub_query[0].id

                # ---- Save Product ----
                product_data = {
                    "name": name,
                    "sku": sku,
                    "category_id": category_id,
                    "subcategory_id": subcategory_id,
                    "brand": brand,
                    "color": color,
                    "description": description,
                    "dimensions": dimensions,
                    "price": price,
                    "stock": stock,
                    "images": image_urls,
                    "created_at": firestore.SERVER_TIMESTAMP,
                    "updated_at": firestore.SERVER_TIMESTAMP
                }

                db.collection("products").document(product_id).set(product_data)
                added_products.append({"row": index + 2, "product_id": product_id, "sku": sku})

            except Exception as row_err:
                errors.append({"row": index + 2, "error": str(row_err)})

        return jsonify({
            "message": "Batch upload completed",
            "added_products": added_products,
            "errors": errors
        }), 200

    except Exception as e:
        print("UNEXPECTED ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500



# -----------------------------------------
# ADD TO CART
# -----------------------------------------
def add_to_cart(request, db, SECRET_KEY):
    try:
        # -------------------------
        # AUTH (ANY LOGGED-IN USER)
        # -------------------------
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        customer_id = payload.get("user_id")
        if not customer_id:
            return jsonify({"error": "Invalid user token"}), 401

        # -------------------------
        # BODY
        # -------------------------
        data = request.get_json()
        product_id = data.get("product_id")
        quantity = int(data.get("quantity", 1))

        if not product_id:
            return jsonify({"error": "product_id is required"}), 400

        if quantity < 1:
            return jsonify({"error": "Quantity must be at least 1"}), 400

        # -------------------------
        # VERIFY PRODUCT EXISTS
        # -------------------------
        product_ref = db.collection("products").document(product_id)
        if not product_ref.get().exists:
            return jsonify({"error": "Product not found"}), 404

        # -------------------------
        # CART ITEM REF
        # -------------------------
        cart_item_ref = (
            db.collection("customers")
            .document(customer_id)
            .collection("cart")
            .document(product_id)
        )

        cart_doc = cart_item_ref.get()

        # -------------------------
        # ADD / UPDATE CART ITEM
        # -------------------------
        if cart_doc.exists:
            cart_item_ref.update({
                "quantity": cart_doc.to_dict().get("quantity", 1) + quantity,
                "updated_at": firestore.SERVER_TIMESTAMP
            })
        else:
            cart_item_ref.set({
                "product_id": product_id,
                "quantity": quantity,
                "added_at": firestore.SERVER_TIMESTAMP,
                "updated_at": firestore.SERVER_TIMESTAMP
            })

        return jsonify({
            "message": "Product added to cart",
            "product_id": product_id,
            "quantity": quantity
        }), 200

    except Exception as e:
        print("ADD TO CART ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500



# -----------------------------------------
# EDIT CART (Quantity)
# -----------------------------------------
def update_cart_quantity(request, db, SECRET_KEY):
    try:
        # -------------------------
        # AUTH
        # -------------------------
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        customer_id = payload.get("user_id")
        if not customer_id:
            return jsonify({"error": "Invalid user token"}), 401

        # -------------------------
        # BODY
        # -------------------------
        data = request.get_json()
        product_id = data.get("product_id")
        quantity = data.get("quantity")

        if not product_id:
            return jsonify({"error": "product_id is required"}), 400

        if quantity is None:
            return jsonify({"error": "quantity is required"}), 400

        try:
            quantity = int(quantity)
        except ValueError:
            return jsonify({"error": "quantity must be an integer"}), 400

        if quantity < 1:
            return jsonify({"error": "Quantity must be at least 1"}), 400

        # -------------------------
        # CART ITEM REF
        # -------------------------
        cart_item_ref = (
            db.collection("customers")
            .document(customer_id)
            .collection("cart")
            .document(product_id)
        )

        cart_doc = cart_item_ref.get()

        if not cart_doc.exists:
            return jsonify({"error": "Cart item not found"}), 404

        # -------------------------
        # UPDATE QUANTITY
        # -------------------------
        cart_item_ref.update({
            "quantity": quantity,
            "updated_at": firestore.SERVER_TIMESTAMP
        })

        return jsonify({
            "message": "Cart quantity updated",
            "product_id": product_id,
            "quantity": quantity
        }), 200

    except Exception as e:
        print("UPDATE CART ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500



# -----------------------------------------
# REMOVE FROM CART
# -----------------------------------------
def delete_from_cart(request, db, SECRET_KEY):
    try:
        # -------------------------
        # AUTH
        # -------------------------
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        customer_id = payload.get("user_id")
        if not customer_id:
            return jsonify({"error": "Invalid user token"}), 401

        # -------------------------
        # QUERY PARAM
        # -------------------------
        product_id = request.args.get("product_id")

        if not product_id:
            return jsonify({"error": "product_id is required"}), 400

        # -------------------------
        # CART ITEM REF
        # -------------------------
        cart_item_ref = (
            db.collection("customers")
            .document(customer_id)
            .collection("cart")
            .document(product_id)
        )

        cart_doc = cart_item_ref.get()
        if not cart_doc.exists:
            return jsonify({"error": "Cart item not found"}), 404

        # -------------------------
        # DELETE CART ITEM
        # -------------------------
        cart_item_ref.delete()

        return jsonify({
            "message": "Item removed from cart",
            "product_id": product_id
        }), 200

    except Exception as e:
        print("DELETE CART ITEM ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

        
# -----------------------------------------
# CLEAR CART
# -----------------------------------------
def clear_cart(request, db, SECRET_KEY):
    try:
        # -------------------------
        # AUTH
        # -------------------------
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        customer_id = payload.get("user_id")
        if not customer_id:
            return jsonify({"error": "Invalid user token"}), 401

        # -------------------------
        # GET ALL CART ITEMS
        # -------------------------
        cart_ref = (
            db.collection("customers")
            .document(customer_id)
            .collection("cart")
        )

        cart_items = cart_ref.stream()

        deleted_count = 0

        # -------------------------
        # DELETE EVERYTHING
        # -------------------------
        for doc in cart_items:
            doc.reference.delete()
            deleted_count += 1

        return jsonify({
            "message": "Cart cleared successfully",
            "items_removed": deleted_count
        }), 200

    except Exception as e:
        print("CLEAR CART ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# ADD TO WISHLIST
# -----------------------------------------
def add_to_wishlist(request, db, SECRET_KEY):
    try:
        # -------- AUTH --------
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({"error": "Invalid token"}), 401

        customer_id = payload.get("user_id")
        if not customer_id:
            return jsonify({"error": "Invalid user"}), 401

        # -------- QUERY --------
        product_id = request.args.get("product_id")
        if not product_id:
            return jsonify({"error": "product_id is required"}), 400

        wishlist_ref = (
            db.collection("customers")
            .document(customer_id)
            .collection("wishlist")
            .document(product_id)
        )

        wishlist_ref.set({
            "product_id": product_id,
            "added_at": firestore.SERVER_TIMESTAMP
        })

        return jsonify({"message": "Added to wishlist", "product_id": product_id}), 200

    except Exception as e:
        print("ADD WISHLIST ERROR:", e)
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# CLEAR WISHLIST
# -----------------------------------------
def clear_wishlist(request, db, SECRET_KEY):
    try:
        # -------- AUTH --------
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({"error": "Invalid token"}), 401

        customer_id = payload.get("user_id")
        if not customer_id:
            return jsonify({"error": "Invalid user"}), 401

        wishlist_ref = (
            db.collection("customers")
            .document(customer_id)
            .collection("wishlist")
        )

        deleted = 0
        for doc in wishlist_ref.stream():
            doc.reference.delete()
            deleted += 1

        return jsonify({
            "message": "Wishlist cleared",
            "items_removed": deleted
        }), 200

    except Exception as e:
        print("CLEAR WISHLIST ERROR:", e)
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# DELETE FROM WISHLIST
# -----------------------------------------
def delete_from_wishlist(request, db, SECRET_KEY):
    try:
        # -------- AUTH --------
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({"error": "Invalid token"}), 401

        customer_id = payload.get("user_id")
        if not customer_id:
            return jsonify({"error": "Invalid user"}), 401

        product_id = request.args.get("product_id")
        if not product_id:
            return jsonify({"error": "product_id is required"}), 400

        wishlist_item = (
            db.collection("customers")
            .document(customer_id)
            .collection("wishlist")
            .document(product_id)
        )

        if not wishlist_item.get().exists:
            return jsonify({"error": "Item not found"}), 404

        wishlist_item.delete()

        return jsonify({"message": "Removed from wishlist", "product_id": product_id}), 200

    except Exception as e:
        print("DELETE WISHLIST ERROR:", e)
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# MOVE FROM WISHLIST TO CART
# -----------------------------------------
def move_wishlist_to_cart(request, db, SECRET_KEY):
    try:
        # -------- AUTH --------
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({"error": "Invalid token"}), 401

        customer_id = payload.get("user_id")
        if not customer_id:
            return jsonify({"error": "Invalid user"}), 401

        product_id = request.args.get("product_id")
        if not product_id:
            return jsonify({"error": "product_id is required"}), 400

        customer_ref = db.collection("customers").document(customer_id)

        wishlist_item = customer_ref.collection("wishlist").document(product_id)
        if not wishlist_item.get().exists:
            return jsonify({"error": "Item not in wishlist"}), 404

        cart_item = customer_ref.collection("cart").document(product_id)
        cart_doc = cart_item.get()

        if cart_doc.exists:
            cart_item.update({
                "quantity": firestore.Increment(1),
                "updated_at": firestore.SERVER_TIMESTAMP
            })
        else:
            cart_item.set({
                "product_id": product_id,
                "quantity": 1,
                "added_at": firestore.SERVER_TIMESTAMP
            })

        wishlist_item.delete()

        return jsonify({
            "message": "Moved from wishlist to cart",
            "product_id": product_id
        }), 200

    except Exception as e:
        print("MOVE WISHLIST ERROR:", e)
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# CHECKOUT ITEMS
# -----------------------------------------



# -----------------------------------------
# MOVE CHECKOUT ITEMS BACK TO CART
# -----------------------------------------



# -----------------------------------------
# PROCESS CHECKOUT (ORDER - QUOTE)
# -----------------------------------------



# -----------------------------------------
# CONFIRM ORDER
# -----------------------------------------



# -----------------------------------------
# CANCEL ORDER
# -----------------------------------------



# -----------------------------------------
# SET DELIVERY ADDRESS FOR ORDER (MANUAL ENTRY OR AUTOMATIC FROM ADDRESS BOOK)
# -----------------------------------------



# -----------------------------------------
# CONFRIM DELIVERY
# -----------------------------------------



# -----------------------------------------
# CONFIRM PAYMENT (CLIENTS ARE GIVEN UP TO A MONTH)
# -----------------------------------------



# -----------------------------------------
# GET QUOTE (NON-CART ITEM)
# -----------------------------------------



