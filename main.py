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
# Helper: audit log
# -----------------------------------------
def log_action(user_id, email, role, action, details=None):
    try:
        db.collection("audit_logs").add({
            "user_id": user_id,
            "email": email,
            "role": role,
            "action": action,
            "details": details or {},
            "timestamp": firestore.SERVER_TIMESTAMP
        })
    except Exception as e:
        print(f"AUDIT LOG ERROR: {e}")


# -----------------------------------------
# Helper: detect URL type and download image
# -----------------------------------------
def is_google_photos_url(url):
    """Check if a URL is a Google Photos shared link."""
    return "photos.app.goo.gl" in url or "photos.google.com/share" in url


def is_google_drive_url(url):
    """Check if a URL is a Google Drive shared link."""
    return "drive.google.com" in url or "docs.google.com" in url


def extract_google_photos_images(url):
    """
    Extract image download URLs from a Google Photos shared link.
    Returns a list of (download_url, content_type) tuples.
    """
    try:
        # Follow redirects for short links (photos.app.goo.gl)
        session = requests.Session()
        resp = session.get(url, timeout=15)
        resp.raise_for_status()

        html = resp.text

        # Extract lh3.googleusercontent.com URLs from the page HTML
        # These appear in embedded script/data with various size suffixes
        raw_urls = re.findall(
            r'(https://lh3\.googleusercontent\.com/pw/[A-Za-z0-9_\-/]+)',
            html
        )

        if not raw_urls:
            # Fallback: broader pattern for any lh3 image URL
            raw_urls = re.findall(
                r'(https://lh3\.googleusercontent\.com/[A-Za-z0-9_\-/]+)',
                html
            )

        # Deduplicate while preserving order
        seen = set()
        unique_urls = []
        for u in raw_urls:
            # Strip any existing size params (=w123, =s123, etc.)
            base = re.split(r'=(?:w|h|s|d)\d*', u)[0]
            if base not in seen:
                seen.add(base)
                unique_urls.append(base)

        # Filter out profile/icon URLs (they tend to be short paths)
        image_urls = [u for u in unique_urls if len(u) > 80]

        # Append =d for full-resolution download
        download_urls = [f"{u}=d" for u in image_urls]
        return download_urls

    except Exception as e:
        print(f"Failed to extract Google Photos images: {e}")
        return []




# -----------------------------------------
# Cloud Function main entry
# -----------------------------------------
@functions_framework.http
def app(request):
    # Handle CORS preflight requests
    if request.method == "OPTIONS":
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "3600",
        }
        return ("", 204, headers)

    # Add CORS headers to all responses
    cors_headers = {"Access-Control-Allow-Origin": "*"}

    def add_cors(response):
        if isinstance(response, tuple):
            if len(response) == 2:
                body, status = response
                return (body, status, cors_headers)
            elif len(response) == 3:
                body, status, headers = response
                if isinstance(headers, dict):
                    headers.update(cors_headers)
                return (body, status, headers)
        return response

    request_json = request.get_json(silent=True) or {}
    path = request.path.lower()

    # ---- ROUTES ----
    result = None

    if path == "/signup":
        result = signup(request_json)
    elif path == "/login":
        result = login(request_json)
    elif path == "/add-address":
        result = add_address(request_json)
    elif path == "/edit-address":
        result = edit_address(request_json)
    elif path == "/list-addresses":
        result = list_addresses(request_json)
    elif path == "/delete-address":
        result = delete_address(request_json)
    elif path == "/add-notification":
        result = add_notification(request_json)
    elif path == "/list-notifications":
        result = list_notifications(request_json)
    elif path == "/mark-notification-read":
        result = mark_notification_read(request_json)
    elif path == "/add-category":
        result = add_category(request_json)
    elif path == "/list-categories":
        result = list_categories(request_json)
    elif path == "/edit-category":
        result = edit_category(request_json)
    elif path == "/delete-category":
        result = delete_category(request_json)
    elif path == "/add-subcategory":
        result = add_subcategory(request_json)
    elif path == "/edit-subcategory":
        result = edit_subcategory(request_json)
    elif path == "/delete-subcategory":
        result = delete_subcategory(request_json)
    elif path == "/list-subcategories":
        result = list_subcategories(request_json)
    elif path == "/edit-product":
        result = edit_product(request)
    elif path == "/create-product":
        result = create_product(request)
    elif path == "/get-product":
        result = get_product(request, db)
    elif path == "/get-all-products":
        result = get_all_products(request, db)
    elif path == "/delete-product":
        result = delete_product(request, db, bucket, SECRET_KEY)
    elif path == "/add-product-images":
        result = add_product_images(request, db, bucket, SECRET_KEY)
    elif path == "/delete-product-image":
        result = delete_product_images(request, db, bucket, SECRET_KEY)
    elif path == "/validate-batch-upload":
        result = validate_batch_upload(request, db, SECRET_KEY)
    elif path == "/batch-product-upload":
        result = batch_upload_products(request, db, bucket, SECRET_KEY)
    elif path == "/get-cart-items":
        result = get_cart_items(request, db, SECRET_KEY)
    elif path == "/add-to-cart":
        result = add_to_cart(request, db, SECRET_KEY)
    elif path == "/update-cart-quantity":
        result = update_cart_quantity(request, db, SECRET_KEY)
    elif path == "/delete-from-cart":
        result = delete_from_cart(request, db, SECRET_KEY)
    elif path == "/clear-cart":
        result = clear_cart(request, db, SECRET_KEY)
    elif path == "/add-to-wishlist":
        result = add_to_wishlist(request, db, SECRET_KEY)
    elif path == "/delete-from-wishlist":
        result = delete_from_wishlist(request, db, SECRET_KEY)
    elif path == "/clear-wishlist":
        result = clear_wishlist(request, db, SECRET_KEY)
    elif path == "/move-from-wishlist-to-cart":
        result = move_wishlist_to_cart(request, db, SECRET_KEY)
    elif path == "/checkout-items":
        result = checkout_items(request, db, SECRET_KEY)
    elif path == "/move-checkout-to-cart":
        result = move_checkout_to_cart(request, db, SECRET_KEY)
    elif path == "/process-checkout":
        result = process_checkout(request, db, SECRET_KEY)
    elif path == "/confirm-order":
        result = confirm_order(request, db, SECRET_KEY)
    elif path == "/cancel-order":
        result = cancel_order(request, db, SECRET_KEY)
    elif path == "/set-order-address":
        result = set_order_address(request, db, SECRET_KEY)
    elif path == "/confirm-delivery":
        result = confirm_delivery(request, db, SECRET_KEY)
    elif path == "/confirm-payment":
        result = confirm_payment(request, db, SECRET_KEY)
    elif path == "/get-quote":
        result = request_quote(request, db, SECRET_KEY)
    elif path == "/list-customers":
        result = list_customers(request, db, SECRET_KEY)
    elif path == "/list-quotes":
        result = list_quotes(request, db, SECRET_KEY)
    elif path == "/get-quote-detail":
        result = get_quote_detail(request, db, SECRET_KEY)
    elif path == "/get-logs":
        result = get_logs(request, db, SECRET_KEY)
    elif path == "/change-user-role":
        result = change_user_role(request, db, SECRET_KEY)
    elif path == "/dashboard-stats":
        result = dashboard_stats(request, db, SECRET_KEY)
    elif path == "/get-customer-profile":
        result = get_customer_profile(request, db, SECRET_KEY)
    elif path == "/update-customer-profile":
        result = update_customer_profile(request, db, SECRET_KEY)
    elif path == "/get-all-blogs":
        result = get_all_blogs(request, db)
    elif path == "/get-blog":
        result = get_blog(request, db)
    elif path == "/create-blog":
        result = create_blog(request, db, SECRET_KEY)
    elif path == "/subscribe-newsletter":
        result = subscribe_newsletter(request, db)
    elif path == "/submit-contact":
        result = submit_contact(request, db)
    elif path == "/submit-inquiry":
        result = submit_inquiry(request, db, SECRET_KEY)
    elif path == "/get-wishlist":
        result = get_wishlist(request, db, SECRET_KEY)
    elif path == "/apply-coupon":
        result = apply_coupon(request, db, SECRET_KEY)
    else:
        result = (jsonify({"error": "Endpoint not found"}), 404)

    return add_cors(result)


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
    log_action(user_id, email, "customer", "signup")

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
    log_action(user_doc.id, user["email"], user["role"], "login")

    return jsonify({
        "message": "Login successful",
        "user_id": user_doc.id,
        "token": token,
        "role": user["role"]
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
    log_action(user_id, payload.get("email"), payload.get("role", "customer"), "add_address", {"address_id": address_id})

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
    log_action(user_id, payload.get("email"), payload.get("role", "customer"), "edit_address", {"address_id": address_id})

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

    log_action(user_id, payload.get("email"), payload.get("role", "customer"), "delete_address", {"address_id": address_id})

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

    log_action(payload.get("user_id"), payload.get("email"), role, "send_notification", {"user_ids": user_ids, "title": data["title"]})

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

    log_action(payload.get("user_id"), payload.get("email"), role, "create_category", {"category_id": category_id, "name": name, "parent_id": parent_id})

    return jsonify({
        "message": "Category added successfully",
        "category_id": category_id,
        "parent_id": parent_id
    }), 201


# -----------------------------------------
# VIEW ALL CATEGORIES (ALL USERS)
# -----------------------------------------
def list_categories(_):
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
    log_action(payload.get("user_id"), payload.get("email"), role, "update_category", {"category_id": category_id, "parent_id": parent_id})

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
    log_action(payload.get("user_id"), payload.get("email"), role, "delete_category", {"category_id": category_id, "parent_id": parent_id})

    return jsonify({"message": "Category deleted successfully"}), 200


# -----------------------------------------
# ADD SUBCATEGORY (ADMIN ONLY)
# -----------------------------------------
def add_subcategory(data):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token required"}), 401

    token = auth_header.split(" ")[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        role = payload.get("role")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    if role not in ["admin", "sub-admin", "super-admin"]:
        return jsonify({"error": "Only admins can manage subcategories"}), 403

    category_id = data.get("category_id")
    if not category_id:
        return jsonify({"error": "Missing field: category_id"}), 400

    if "name" not in data:
        return jsonify({"error": "Missing field: name"}), 400

    parent_ref = db.collection("categories").document(category_id)
    if not parent_ref.get().exists:
        return jsonify({"error": "Parent category not found"}), 404

    subcategory_id = str(uuid.uuid4())
    subcategory_data = {
        "name": data["name"],
        "description": data.get("description", ""),
        "created_at": firestore.SERVER_TIMESTAMP,
        "updated_at": firestore.SERVER_TIMESTAMP
    }

    parent_ref.collection("subcategories").document(subcategory_id).set(subcategory_data)
    log_action(payload.get("user_id"), payload.get("email"), role, "create_subcategory", {"subcategory_id": subcategory_id, "category_id": category_id})

    return jsonify({
        "message": "Subcategory added successfully",
        "subcategory_id": subcategory_id,
        "category_id": category_id
    }), 201


# -----------------------------------------
# EDIT SUBCATEGORY (ADMIN ONLY)
# -----------------------------------------
def edit_subcategory(data):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token required"}), 401

    token = auth_header.split(" ")[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        role = payload.get("role")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    if role not in ["admin", "sub-admin", "super-admin"]:
        return jsonify({"error": "Only admins can edit subcategories"}), 403

    category_id = data.get("category_id")
    subcategory_id = data.get("subcategory_id")

    if not category_id:
        return jsonify({"error": "Missing field: category_id"}), 400
    if not subcategory_id:
        return jsonify({"error": "Missing field: subcategory_id"}), 400

    update_data = {}
    if "name" in data:
        update_data["name"] = data["name"]
    if "description" in data:
        update_data["description"] = data["description"]

    if not update_data:
        return jsonify({"error": "No fields to update"}), 400

    update_data["updated_at"] = firestore.SERVER_TIMESTAMP

    sub_ref = (
        db.collection("categories")
        .document(category_id)
        .collection("subcategories")
        .document(subcategory_id)
    )

    if not sub_ref.get().exists:
        return jsonify({"error": "Subcategory not found"}), 404

    sub_ref.update(update_data)
    log_action(payload.get("user_id"), payload.get("email"), role, "update_subcategory", {"subcategory_id": subcategory_id, "category_id": category_id})

    return jsonify({"message": "Subcategory updated successfully"}), 200


# -----------------------------------------
# DELETE SUBCATEGORY (ADMIN ONLY)
# -----------------------------------------
def delete_subcategory(data):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token required"}), 401

    token = auth_header.split(" ")[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        role = payload.get("role")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    if role not in ["admin", "sub-admin", "super-admin"]:
        return jsonify({"error": "Only admins can delete subcategories"}), 403

    category_id = data.get("category_id")
    subcategory_id = data.get("subcategory_id")

    if not category_id:
        return jsonify({"error": "Missing field: category_id"}), 400
    if not subcategory_id:
        return jsonify({"error": "Missing field: subcategory_id"}), 400

    sub_ref = (
        db.collection("categories")
        .document(category_id)
        .collection("subcategories")
        .document(subcategory_id)
    )

    if not sub_ref.get().exists:
        return jsonify({"error": "Subcategory not found"}), 404

    sub_ref.delete()
    log_action(payload.get("user_id"), payload.get("email"), role, "delete_subcategory", {"subcategory_id": subcategory_id, "category_id": category_id})

    return jsonify({"message": "Subcategory deleted successfully"}), 200


# -----------------------------------------
# LIST SUBCATEGORIES FOR A CATEGORY
# -----------------------------------------
def list_subcategories(data):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token required"}), 401

    token = auth_header.split(" ")[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    category_id = data.get("category_id") or request.args.get("category_id")
    if not category_id:
        return jsonify({"error": "Missing field: category_id"}), 400

    parent_ref = db.collection("categories").document(category_id)
    if not parent_ref.get().exists:
        return jsonify({"error": "Category not found"}), 404

    sub_docs = parent_ref.collection("subcategories").get()
    subcategories = []
    for sub in sub_docs:
        sub_data = sub.to_dict()
        sub_data["subcategory_id"] = sub.id
        subcategories.append(sub_data)

    return jsonify({
        "category_id": category_id,
        "subcategories": subcategories
    }), 200


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
                "category_name": category_name,
                "subcategory_name": subcategory_name,
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

        log_action(payload.get("user_id"), payload.get("email"), role, "create_product", {"product_id": product_id, "sku": sku})

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
        log_action(payload.get("user_id"), payload.get("email"), role, "delete_product", {"product_id": product_id})

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
            "sku",
            "category_id",
            "subcategory_id",
            "category_name",
            "subcategory_name",
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
        log_action(payload.get("user_id"), payload.get("email"), role, "update_product", {"product_id": product_id, "updated_fields": list(update_data.keys())})

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
        log_action(payload.get("user_id"), payload.get("email"), role, "delete_product_images", {"product_id": product_id, "deleted_count": len(deleted)})

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
        log_action(payload.get("user_id"), payload.get("email"), role, "add_product_images", {"product_id": product_id, "added_count": len(new_image_urls)})

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
# VALIDATE BATCH UPLOAD
# -----------------------------------------
def validate_batch_upload(request, db, SECRET_KEY):
    try:
        import pandas as pd
        from flask import jsonify

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

        filename = uploaded_file.filename
        if filename.endswith(".csv"):
            df = pd.read_csv(uploaded_file)
        elif filename.endswith((".xlsx", ".xls")):
            df = pd.read_excel(uploaded_file)
        else:
            return jsonify({"error": "File must be CSV or Excel"}), 400

        required_columns = ["Name", "SKU", "Category", "Subcategory", "Price"]
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            return jsonify({"error": f"Missing required columns: {', '.join(missing_columns)}"}), 400

        # ---- PRE-FETCH categories & subcategories ----
        all_categories = {}
        for cat_doc in db.collection("categories").get():
            cat_data = cat_doc.to_dict()
            cat_name = cat_data.get("name", "")
            subcats = {}
            for sub_doc in cat_doc.reference.collection("subcategories").get():
                sub_data = sub_doc.to_dict()
                subcats[sub_data.get("name", "")] = sub_doc.id
            all_categories[cat_name] = {"id": cat_doc.id, "subcategories": subcats}

        # ---- Check for duplicate SKUs in file ----
        file_skus = df["SKU"].astype(str).str.strip().tolist()
        sku_seen = {}
        file_sku_duplicates = {}
        for i, s in enumerate(file_skus):
            if s in sku_seen:
                if s not in file_sku_duplicates:
                    file_sku_duplicates[s] = [sku_seen[s]]
                file_sku_duplicates[s].append(i + 2)
            else:
                sku_seen[s] = i + 2

        # ---- Check existing SKUs in DB ----
        existing_skus = set()
        for s in set(file_skus):
            if db.collection("products").where("sku", "==", s).limit(1).get():
                existing_skus.add(s)

        # ---- Validate each row ----
        validation_rows = []

        for index, row in df.iterrows():
            row_num = index + 2
            row_errors = []
            row_warnings = []

            name = str(row["Name"]).strip() if not pd.isna(row["Name"]) else ""
            sku = str(row["SKU"]).strip() if not pd.isna(row["SKU"]) else ""
            category_name = str(row["Category"]).strip() if not pd.isna(row["Category"]) else ""
            subcategory_name = str(row["Subcategory"]).strip() if not pd.isna(row["Subcategory"]) else ""
            price_raw = row["Price"]

            if not name:
                row_errors.append("Missing required field: Name")
            if not sku:
                row_errors.append("Missing required field: SKU")
            if not category_name:
                row_errors.append("Missing required field: Category")
            if not subcategory_name:
                row_errors.append("Missing required field: Subcategory")

            if pd.isna(price_raw):
                row_errors.append("Missing required field: Price")
            else:
                try:
                    float(price_raw)
                except (ValueError, TypeError):
                    row_errors.append(f"Price must be a number, got: '{price_raw}'")

            if "Stock" in row and not pd.isna(row["Stock"]):
                try:
                    int(row["Stock"])
                except (ValueError, TypeError):
                    row_errors.append(f"Stock must be an integer, got: '{row['Stock']}'")

            if sku and sku in existing_skus:
                row_errors.append("SKU already exists in database")

            if sku and sku in file_sku_duplicates:
                other_rows = [r for r in file_sku_duplicates[sku] if r != row_num]
                if other_rows:
                    row_errors.append(f"Duplicate SKU in file (also in row {', '.join(map(str, other_rows))})")

            if category_name and category_name not in all_categories:
                row_errors.append(f"Category '{category_name}' not found")
            elif category_name and subcategory_name:
                cat_info = all_categories[category_name]
                if subcategory_name not in cat_info["subcategories"]:
                    row_errors.append(f"Subcategory '{subcategory_name}' not found under '{category_name}'")

            if "Image URLs" in row and not pd.isna(row["Image URLs"]):
                urls = [u.strip() for u in str(row["Image URLs"]).split(",")]
                for u in urls:
                    if not u.startswith("http://") and not u.startswith("https://"):
                        row_errors.append(f"Invalid image URL: '{u}'")
            else:
                row_warnings.append("No image URLs provided")

            status = "valid" if not row_errors else "invalid"
            validation_rows.append({
                "row": row_num,
                "name": name,
                "sku": sku,
                "category": category_name,
                "subcategory": subcategory_name,
                "status": status,
                "errors": row_errors,
                "warnings": row_warnings
            })

        valid_count = sum(1 for r in validation_rows if r["status"] == "valid")
        invalid_count = sum(1 for r in validation_rows if r["status"] == "invalid")

        return jsonify({
            "validation": True,
            "total_rows": len(validation_rows),
            "valid_rows": valid_count,
            "invalid_rows": invalid_count,
            "rows": validation_rows
        }), 200

    except Exception as e:
        import traceback
        print("VALIDATE BATCH ERROR:", str(e))
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

        required_columns = ["Name", "SKU", "Category", "Subcategory", "Price"]
        for col in required_columns:
            if col not in df.columns:
                return jsonify({"error": f"Missing required column: {col}"}), 400

        validate_only = request.args.get("validate", "").lower() == "true"

        # ---- PRE-FETCH categories & subcategories for validation ----
        all_categories = {}  # { name: { "id": ..., "subcategories": { name: id } } }
        for cat_doc in db.collection("categories").get():
            cat_data = cat_doc.to_dict()
            cat_name = cat_data.get("name", "")
            subcats = {}
            for sub_doc in cat_doc.reference.collection("subcategories").get():
                sub_data = sub_doc.to_dict()
                subcats[sub_data.get("name", "")] = sub_doc.id
            all_categories[cat_name] = {"id": cat_doc.id, "subcategories": subcats}

        # ---- PRE-CHECK for duplicate SKUs in file ----
        file_skus = df["SKU"].astype(str).str.strip().tolist()
        sku_seen = {}  # { sku: first_row }
        file_sku_duplicates = {}  # { sku: [row_numbers] }
        for i, s in enumerate(file_skus):
            if s in sku_seen:
                if s not in file_sku_duplicates:
                    file_sku_duplicates[s] = [sku_seen[s]]
                file_sku_duplicates[s].append(i + 2)
            else:
                sku_seen[s] = i + 2

        # ---- PRE-CHECK existing SKUs in DB ----
        existing_skus = set()
        for s in set(file_skus):
            if db.collection("products").where("sku", "==", s).limit(1).get():
                existing_skus.add(s)

        # ---- VALIDATION MODE ----
        if validate_only:
            validation_rows = []

            for index, row in df.iterrows():
                row_num = index + 2
                row_errors = []
                row_warnings = []

                # Required fields
                name = str(row["Name"]).strip() if not pd.isna(row["Name"]) else ""
                sku = str(row["SKU"]).strip() if not pd.isna(row["SKU"]) else ""
                category_name = str(row["Category"]).strip() if not pd.isna(row["Category"]) else ""
                subcategory_name = str(row["Subcategory"]).strip() if not pd.isna(row["Subcategory"]) else ""
                price_raw = row["Price"]

                if not name:
                    row_errors.append("Missing required field: Name")
                if not sku:
                    row_errors.append("Missing required field: SKU")
                if not category_name:
                    row_errors.append("Missing required field: Category")
                if not subcategory_name:
                    row_errors.append("Missing required field: Subcategory")

                # Price type check
                if pd.isna(price_raw):
                    row_errors.append("Missing required field: Price")
                else:
                    try:
                        float(price_raw)
                    except (ValueError, TypeError):
                        row_errors.append(f"Price must be a number, got: '{price_raw}'")

                # Stock type check
                if "Stock" in row and not pd.isna(row["Stock"]):
                    try:
                        int(row["Stock"])
                    except (ValueError, TypeError):
                        row_errors.append(f"Stock must be an integer, got: '{row['Stock']}'")

                # SKU uniqueness - in DB
                if sku and sku in existing_skus:
                    row_errors.append("SKU already exists in database")

                # SKU uniqueness - in file
                if sku and sku in file_sku_duplicates:
                    other_rows = [r for r in file_sku_duplicates[sku] if r != row_num]
                    if other_rows:
                        row_errors.append(f"Duplicate SKU in file (also in row {', '.join(map(str, other_rows))})")

                # Category exists
                if category_name and category_name not in all_categories:
                    row_errors.append(f"Category '{category_name}' not found")
                elif category_name and subcategory_name:
                    # Subcategory exists under that category
                    cat_info = all_categories[category_name]
                    if subcategory_name not in cat_info["subcategories"]:
                        row_errors.append(f"Subcategory '{subcategory_name}' not found under '{category_name}'")

                # Image URL validation
                if "Image URLs" in row and not pd.isna(row["Image URLs"]):
                    urls = [u.strip() for u in str(row["Image URLs"]).split(",")]
                    for u in urls:
                        if not u.startswith("http://") and not u.startswith("https://"):
                            row_errors.append(f"Invalid image URL: '{u}'")
                else:
                    row_warnings.append("No image URLs provided")

                status = "valid" if not row_errors else "invalid"
                validation_rows.append({
                    "row": row_num,
                    "name": name,
                    "sku": sku,
                    "category": category_name,
                    "subcategory": subcategory_name,
                    "status": status,
                    "errors": row_errors,
                    "warnings": row_warnings
                })

            valid_count = sum(1 for r in validation_rows if r["status"] == "valid")
            invalid_count = sum(1 for r in validation_rows if r["status"] == "invalid")

            return jsonify({
                "validation": True,
                "total_rows": len(validation_rows),
                "valid_rows": valid_count,
                "invalid_rows": invalid_count,
                "rows": validation_rows
            }), 200

        # ---- NORMAL UPLOAD MODE ----
        added_products = []
        errors = []

        for index, row in df.iterrows():
            try:
                name = str(row["Name"]).strip()
                sku = str(row["SKU"]).strip()
                category_name = str(row["Category"]).strip()
                subcategory_name = str(row["Subcategory"]).strip()
                price = float(row["Price"])
                stock = int(row["Stock"]) if "Stock" in row and not pd.isna(row["Stock"]) else 0
                brand = str(row["Brand"]).strip() if "Brand" in row and not pd.isna(row["Brand"]) else ""
                color = str(row["Color"]).strip() if "Color" in row and not pd.isna(row["Color"]) else ""
                description = str(row["Description"]).strip() if "Description" in row and not pd.isna(row["Description"]) else ""
                dimensions = str(row["Dimensions"]).strip() if "Dimensions" in row and not pd.isna(row["Dimensions"]) else ""

                # Generate product ID now, used for folder
                product_id = str(uuid.uuid4())

                image_urls = []
                if "Image URLs" in row and not pd.isna(row["Image URLs"]):
                    raw_urls = [url.strip() for url in str(row["Image URLs"]).split(",")]
                    safe_name = name.replace(" ", "_")
                    seq = 1

                    for source_url in raw_urls:
                        try:
                            if is_google_photos_url(source_url):
                                # Google Photos: extract all images from the shared link
                                photo_urls = extract_google_photos_images(source_url)
                                for photo_url in photo_urls:
                                    try:
                                        resp = requests.get(photo_url, stream=True, timeout=30)
                                        if resp.status_code != 200:
                                            print(f"Failed to download Google Photos image: HTTP {resp.status_code}")
                                            continue

                                        content_type = resp.headers.get("Content-Type", "image/jpeg")
                                        ext = "jpg"
                                        if "png" in content_type:
                                            ext = "png"
                                        elif "jpeg" in content_type or "jpg" in content_type:
                                            ext = "jpg"

                                        filename_seq = f"{safe_name}_{str(seq).zfill(3)}.{ext}"
                                        blob_name = f"products/{product_id}/{filename_seq}"
                                        blob = bucket.blob(blob_name)
                                        blob.upload_from_file(resp.raw, content_type=content_type)

                                        image_urls.append(blob.public_url)
                                        seq += 1
                                    except Exception as photo_err:
                                        print(f"Failed to download Google Photos image: {photo_err}")
                                        continue

                            elif is_google_drive_url(source_url):
                                # Google Drive: extract file ID and download
                                file_id_match = re.search(r"/d/([a-zA-Z0-9_-]+)", source_url)
                                if not file_id_match:
                                    file_id_match = re.search(r"id=([a-zA-Z0-9_-]+)", source_url)
                                if not file_id_match:
                                    continue
                                file_id = file_id_match.group(1)
                                download_url = f"https://drive.google.com/uc?export=download&id={file_id}"

                                resp = requests.get(download_url, stream=True, timeout=30)
                                if resp.status_code != 200:
                                    continue

                                ext = source_url.split(".")[-1].lower()
                                if ext not in ["jpg", "jpeg", "png"]:
                                    ext = "jpg"

                                filename_seq = f"{safe_name}_{str(seq).zfill(3)}.{ext}"
                                blob_name = f"products/{product_id}/{filename_seq}"
                                blob = bucket.blob(blob_name)
                                blob.upload_from_file(resp.raw, content_type=resp.headers.get("Content-Type", "image/jpeg"))

                                image_urls.append(blob.public_url)
                                seq += 1

                            else:
                                # Direct image URL fallback
                                resp = requests.get(source_url, stream=True, timeout=30)
                                if resp.status_code != 200:
                                    continue

                                content_type = resp.headers.get("Content-Type", "image/jpeg")
                                ext = "jpg"
                                if "png" in content_type:
                                    ext = "png"

                                filename_seq = f"{safe_name}_{str(seq).zfill(3)}.{ext}"
                                blob_name = f"products/{product_id}/{filename_seq}"
                                blob = bucket.blob(blob_name)
                                blob.upload_from_file(resp.raw, content_type=content_type)

                                image_urls.append(blob.public_url)
                                seq += 1

                        except Exception as img_err:
                            print(f"Failed to process image {source_url}: {img_err}")
                            continue

                # ---- Use pre-fetched category data for lookup ----
                if category_name not in all_categories:
                    errors.append({"row": index + 2, "sku": sku, "error": f"Category '{category_name}' not found"})
                    continue
                cat_info = all_categories[category_name]
                category_id = cat_info["id"]

                if subcategory_name not in cat_info["subcategories"]:
                    errors.append({"row": index + 2, "sku": sku, "error": f"Subcategory '{subcategory_name}' not found"})
                    continue
                subcategory_id = cat_info["subcategories"][subcategory_name]

                # ---- Check SKU uniqueness ----
                if sku in existing_skus:
                    errors.append({"row": index + 2, "sku": sku, "error": "SKU already exists"})
                    continue

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

        log_action(payload.get("user_id"), payload.get("email"), role, "batch_upload_products", {"added_count": len(added_products), "error_count": len(errors)})

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
# GET CART ITEMS
# -----------------------------------------
def get_cart_items(request, db, SECRET_KEY):
    try:
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

        cart_ref = (
            db.collection("customers")
            .document(customer_id)
            .collection("cart")
        )

        cart_items = []
        for doc in cart_ref.stream():
            item = doc.to_dict()
            item["product_id"] = doc.id
            cart_items.append(item)

        return jsonify({
            "cart_items": cart_items,
            "total_items": len(cart_items)
        }), 200

    except Exception as e:
        print("GET CART ITEMS ERROR:", str(e))
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

        log_action(customer_id, payload.get("email"), payload.get("role", "customer"), "add_to_cart", {"product_id": product_id, "quantity": quantity})

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
        log_action(customer_id, payload.get("email"), payload.get("role", "customer"), "delete_from_cart", {"product_id": product_id})

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

        log_action(customer_id, payload.get("email"), payload.get("role", "customer"), "clear_cart", {"items_removed": deleted_count})

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

        log_action(customer_id, payload.get("email"), payload.get("role", "customer"), "add_to_wishlist", {"product_id": product_id})

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

        log_action(customer_id, payload.get("email"), payload.get("role", "customer"), "clear_wishlist", {"items_removed": deleted})

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
        log_action(customer_id, payload.get("email"), payload.get("role", "customer"), "delete_from_wishlist", {"product_id": product_id})

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
        log_action(customer_id, payload.get("email"), payload.get("role", "customer"), "move_to_cart", {"product_id": product_id})

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
def checkout_items(request, db, SECRET_KEY):
    try:
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

        data = request.get_json()
        product_ids = data.get("product_ids")
        if not product_ids or not isinstance(product_ids, list):
            return jsonify({"error": "product_ids list is required"}), 400

        customer_ref = db.collection("customers").document(customer_id)
        checkout_items_list = []

        for product_id in product_ids:
            cart_item_ref = customer_ref.collection("cart").document(product_id)
            cart_doc = cart_item_ref.get()

            if not cart_doc.exists:
                continue

            cart_data = cart_doc.to_dict()

            customer_ref.collection("checkout").document(product_id).set(cart_data)
            cart_item_ref.delete()

            checkout_items_list.append({"product_id": product_id, **cart_data})

        log_action(customer_id, payload.get("email"), payload.get("role", "customer"), "checkout", {"item_count": len(checkout_items_list)})

        return jsonify({
            "message": "Items moved to checkout",
            "checkout_items": checkout_items_list
        }), 200

    except Exception as e:
        print("CHECKOUT ITEMS ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# MOVE CHECKOUT ITEMS BACK TO CART
# -----------------------------------------
def move_checkout_to_cart(request, db, SECRET_KEY):
    try:
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

        data = request.get_json()
        product_ids = data.get("product_ids") if data else None

        customer_ref = db.collection("customers").document(customer_id)
        moved_items = []

        if product_ids and isinstance(product_ids, list):
            checkout_docs = [
                customer_ref.collection("checkout").document(pid).get()
                for pid in product_ids
            ]
        else:
            checkout_docs = list(customer_ref.collection("checkout").stream())

        for doc in checkout_docs:
            if not doc.exists:
                continue

            checkout_data = doc.to_dict()
            product_id = doc.id

            cart_item_ref = customer_ref.collection("cart").document(product_id)
            cart_doc = cart_item_ref.get()

            if cart_doc.exists:
                cart_item_ref.update({
                    "quantity": cart_doc.to_dict().get("quantity", 1) + checkout_data.get("quantity", 1),
                    "updated_at": firestore.SERVER_TIMESTAMP
                })
            else:
                cart_item_ref.set(checkout_data)

            doc.reference.delete()
            moved_items.append(product_id)

        log_action(customer_id, payload.get("email"), payload.get("role", "customer"), "move_checkout_to_cart", {"moved_count": len(moved_items)})

        return jsonify({
            "message": "Items moved back to cart",
            "moved_product_ids": moved_items
        }), 200

    except Exception as e:
        print("MOVE CHECKOUT TO CART ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# PROCESS CHECKOUT (ORDER - QUOTE)
# -----------------------------------------
def process_checkout(request, db, SECRET_KEY):
    try:
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

        customer_ref = db.collection("customers").document(customer_id)
        checkout_docs = list(customer_ref.collection("checkout").stream())

        if not checkout_docs:
            return jsonify({"error": "No items in checkout"}), 400

        order_items = []
        subtotal = 0.0

        for doc in checkout_docs:
            checkout_data = doc.to_dict()
            product_id = doc.id
            quantity = checkout_data.get("quantity", 1)

            product_doc = db.collection("products").document(product_id).get()
            if not product_doc.exists:
                continue

            product_data = product_doc.to_dict()
            price = float(product_data.get("price", 0))
            line_total = price * quantity

            order_items.append({
                "product_id": product_id,
                "name": product_data.get("name", ""),
                "sku": product_data.get("sku", ""),
                "price": price,
                "quantity": quantity
            })

            subtotal += line_total

        if not order_items:
            return jsonify({"error": "No valid products found in checkout"}), 400

        order_id = str(uuid.uuid4())
        payment_due_date = datetime.datetime.utcnow() + datetime.timedelta(days=30)

        order_data = {
            "customer_id": customer_id,
            "items": order_items,
            "subtotal": subtotal,
            "status": "quoted",
            "delivery_address": None,
            "payment_due_date": payment_due_date,
            "created_at": firestore.SERVER_TIMESTAMP,
            "updated_at": firestore.SERVER_TIMESTAMP
        }

        db.collection("orders").document(order_id).set(order_data)

        for doc in checkout_docs:
            doc.reference.delete()

        log_action(customer_id, payload.get("email"), payload.get("role", "customer"), "process_checkout", {"order_id": order_id, "subtotal": subtotal})

        return jsonify({
            "message": "Order created",
            "order_id": order_id,
            "items": order_items,
            "subtotal": subtotal
        }), 201

    except Exception as e:
        print("PROCESS CHECKOUT ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# CONFIRM ORDER
# -----------------------------------------
def confirm_order(request, db, SECRET_KEY):
    try:
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

        user_id = payload.get("user_id")
        role = payload.get("role")

        data = request.get_json()
        order_id = data.get("order_id")
        if not order_id:
            return jsonify({"error": "order_id is required"}), 400

        order_ref = db.collection("orders").document(order_id)
        order_doc = order_ref.get()

        if not order_doc.exists:
            return jsonify({"error": "Order not found"}), 404

        order_data = order_doc.to_dict()

        is_admin = role in ["admin", "sub-admin", "super-admin"]
        is_owner = order_data.get("customer_id") == user_id

        if not is_admin and not is_owner:
            return jsonify({"error": "Unauthorized"}), 403

        if order_data.get("status") != "quoted":
            return jsonify({"error": "Order can only be confirmed when status is 'quoted'"}), 400

        order_ref.update({
            "status": "confirmed",
            "updated_at": firestore.SERVER_TIMESTAMP
        })
        log_action(user_id, payload.get("email"), role, "confirm_order", {"order_id": order_id})

        return jsonify({
            "message": "Order confirmed",
            "order_id": order_id,
            "status": "confirmed"
        }), 200

    except Exception as e:
        print("CONFIRM ORDER ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# CANCEL ORDER
# -----------------------------------------
def cancel_order(request, db, SECRET_KEY):
    try:
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

        user_id = payload.get("user_id")
        role = payload.get("role")

        data = request.get_json()
        order_id = data.get("order_id")
        if not order_id:
            return jsonify({"error": "order_id is required"}), 400

        order_ref = db.collection("orders").document(order_id)
        order_doc = order_ref.get()

        if not order_doc.exists:
            return jsonify({"error": "Order not found"}), 404

        order_data = order_doc.to_dict()

        is_admin = role in ["admin", "sub-admin", "super-admin"]
        is_owner = order_data.get("customer_id") == user_id

        if not is_admin and not is_owner:
            return jsonify({"error": "Unauthorized"}), 403

        if order_data.get("status") not in ["quoted", "confirmed"]:
            return jsonify({"error": "Order can only be cancelled when status is 'quoted' or 'confirmed'"}), 400

        order_ref.update({
            "status": "cancelled",
            "updated_at": firestore.SERVER_TIMESTAMP
        })
        log_action(user_id, payload.get("email"), role, "cancel_order", {"order_id": order_id})

        return jsonify({
            "message": "Order cancelled",
            "order_id": order_id,
            "status": "cancelled"
        }), 200

    except Exception as e:
        print("CANCEL ORDER ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# SET DELIVERY ADDRESS FOR ORDER
# -----------------------------------------
def set_order_address(request, db, SECRET_KEY):
    try:
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

        data = request.get_json()
        order_id = data.get("order_id")
        if not order_id:
            return jsonify({"error": "order_id is required"}), 400

        order_ref = db.collection("orders").document(order_id)
        order_doc = order_ref.get()

        if not order_doc.exists:
            return jsonify({"error": "Order not found"}), 404

        order_data = order_doc.to_dict()
        if order_data.get("customer_id") != customer_id:
            return jsonify({"error": "Unauthorized"}), 403

        address_id = data.get("address_id")

        if address_id:
            address_doc = (
                db.collection("customers")
                .document(customer_id)
                .collection("addresses")
                .document(address_id)
                .get()
            )
            if not address_doc.exists:
                return jsonify({"error": "Address not found"}), 404

            address_data = address_doc.to_dict()
            delivery_address = {
                "address_line1": address_data.get("address_line1", ""),
                "address_line2": address_data.get("address_line2", ""),
                "city": address_data.get("city", ""),
                "region": address_data.get("region", ""),
                "country": address_data.get("country", ""),
                "delivery_instructions": address_data.get("delivery_instructions", "")
            }
        else:
            if not data.get("address_line1") or not data.get("city") or not data.get("country"):
                return jsonify({"error": "address_line1, city, and country are required"}), 400

            delivery_address = {
                "address_line1": data.get("address_line1", ""),
                "address_line2": data.get("address_line2", ""),
                "city": data.get("city", ""),
                "region": data.get("region", ""),
                "country": data.get("country", ""),
                "delivery_instructions": data.get("delivery_instructions", "")
            }

        order_ref.update({
            "delivery_address": delivery_address,
            "updated_at": firestore.SERVER_TIMESTAMP
        })
        log_action(customer_id, payload.get("email"), payload.get("role", "customer"), "set_order_address", {"order_id": order_id})

        return jsonify({
            "message": "Delivery address set",
            "order_id": order_id,
            "delivery_address": delivery_address
        }), 200

    except Exception as e:
        print("SET ORDER ADDRESS ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# CONFIRM DELIVERY
# -----------------------------------------
def confirm_delivery(request, db, SECRET_KEY):
    try:
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

        data = request.get_json()
        order_id = data.get("order_id")
        if not order_id:
            return jsonify({"error": "order_id is required"}), 400

        order_ref = db.collection("orders").document(order_id)
        order_doc = order_ref.get()

        if not order_doc.exists:
            return jsonify({"error": "Order not found"}), 404

        order_data = order_doc.to_dict()

        if order_data.get("status") != "confirmed":
            return jsonify({"error": "Order can only be marked delivered when status is 'confirmed'"}), 400

        order_ref.update({
            "status": "delivered",
            "updated_at": firestore.SERVER_TIMESTAMP
        })
        log_action(payload.get("user_id"), payload.get("email"), role, "confirm_delivery", {"order_id": order_id})

        return jsonify({
            "message": "Delivery confirmed",
            "order_id": order_id,
            "status": "delivered"
        }), 200

    except Exception as e:
        print("CONFIRM DELIVERY ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# CONFIRM PAYMENT
# -----------------------------------------
def confirm_payment(request, db, SECRET_KEY):
    try:
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

        data = request.get_json()
        order_id = data.get("order_id")
        if not order_id:
            return jsonify({"error": "order_id is required"}), 400

        order_ref = db.collection("orders").document(order_id)
        order_doc = order_ref.get()

        if not order_doc.exists:
            return jsonify({"error": "Order not found"}), 404

        order_data = order_doc.to_dict()

        if order_data.get("status") != "delivered":
            return jsonify({"error": "Payment can only be confirmed when status is 'delivered'"}), 400

        order_ref.update({
            "status": "paid",
            "updated_at": firestore.SERVER_TIMESTAMP
        })
        log_action(payload.get("user_id"), payload.get("email"), role, "confirm_payment", {"order_id": order_id})

        return jsonify({
            "message": "Payment confirmed",
            "order_id": order_id,
            "status": "paid"
        }), 200

    except Exception as e:
        print("CONFIRM PAYMENT ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# GET QUOTE (NON-CART ITEM)
# -----------------------------------------
def request_quote(request, db, SECRET_KEY):
    try:
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

        data = request.get_json()
        item_description = data.get("item_description")
        if not item_description:
            return jsonify({"error": "item_description is required"}), 400

        quantity = int(data.get("quantity", 1))
        notes = data.get("notes", "")

        quote_id = str(uuid.uuid4())

        quote_data = {
            "customer_id": customer_id,
            "item_description": item_description,
            "quantity": quantity,
            "notes": notes,
            "status": "pending",
            "admin_response": None,
            "quoted_price": None,
            "created_at": firestore.SERVER_TIMESTAMP,
            "updated_at": firestore.SERVER_TIMESTAMP
        }

        db.collection("quotes").document(quote_id).set(quote_data)
        log_action(customer_id, payload.get("email"), payload.get("role", "customer"), "request_quote", {"quote_id": quote_id, "item_description": item_description})

        return jsonify({
            "message": "Quote request submitted",
            "quote_id": quote_id
        }), 201

    except Exception as e:
        print("REQUEST QUOTE ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# LIST CUSTOMERS (Admin Only)
# -----------------------------------------
def list_customers(request, db, SECRET_KEY):
    try:
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

        customers = []
        docs = db.collection("customers").stream()
        for doc in docs:
            customer = doc.to_dict()
            customer["id"] = doc.id
            customer.pop("password_hash", None)
            customers.append(customer)

        return jsonify({
            "count": len(customers),
            "customers": customers
        }), 200

    except Exception as e:
        print("LIST CUSTOMERS ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# LIST QUOTES (Admin Only)
# -----------------------------------------
def list_quotes(request, db, SECRET_KEY):
    try:
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

        query = db.collection("quotes").order_by("created_at", direction=firestore.Query.DESCENDING)

        status_filter = request.args.get("status")
        if status_filter:
            query = query.where("status", "==", status_filter)

        quotes = []
        for doc in query.stream():
            quote = doc.to_dict()
            quote["id"] = doc.id
            quotes.append(quote)

        return jsonify({
            "count": len(quotes),
            "quotes": quotes
        }), 200

    except Exception as e:
        print("LIST QUOTES ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# GET QUOTE DETAIL (Admin Only)
# -----------------------------------------
def get_quote_detail(request, db, SECRET_KEY):
    try:
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

        quote_id = request.args.get("quote_id")
        if not quote_id:
            return jsonify({"error": "quote_id query parameter is required"}), 400

        doc = db.collection("quotes").document(quote_id).get()
        if not doc.exists:
            return jsonify({"error": "Quote not found"}), 404

        quote = doc.to_dict()
        quote["id"] = doc.id

        return jsonify({"quote": quote}), 200

    except Exception as e:
        print("GET QUOTE DETAIL ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# GET AUDIT LOGS (Admin Only)
# -----------------------------------------
def get_logs(request, db, SECRET_KEY):
    try:
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
        if role != "super-admin":
            return jsonify({"error": "Unauthorized - super-admin access only"}), 403

        query = db.collection("audit_logs").order_by("timestamp", direction=firestore.Query.DESCENDING)

        action_filter = request.args.get("action")
        if action_filter:
            query = query.where("action", "==", action_filter)

        role_filter = request.args.get("role")
        if role_filter:
            query = query.where("role", "==", role_filter)

        user_id_filter = request.args.get("user_id")
        if user_id_filter:
            query = query.where("user_id", "==", user_id_filter)

        limit = min(int(request.args.get("limit", 100)), 500)
        query = query.limit(limit)

        logs = []
        for doc in query.stream():
            log_entry = doc.to_dict()
            log_entry["id"] = doc.id
            logs.append(log_entry)

        return jsonify({
            "count": len(logs),
            "logs": logs
        }), 200

    except Exception as e:
        print("GET LOGS ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# DASHBOARD STATS
# -----------------------------------------
def change_user_role(request, db, SECRET_KEY):
    try:
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
        if role != "super-admin":
            return jsonify({"error": "Unauthorized - super-admin access only"}), 403

        data = request.get_json()
        target_user_id = data.get("target_user_id")
        new_role = data.get("new_role")

        if not target_user_id or not new_role:
            return jsonify({"error": "target_user_id and new_role are required"}), 400

        valid_roles = ["customer", "admin", "sub-admin", "super-admin"]
        if new_role not in valid_roles:
            return jsonify({"error": f"Invalid role. Must be one of: {', '.join(valid_roles)}"}), 400

        user_ref = db.collection("users").document(target_user_id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404

        old_role = user_doc.to_dict().get("role", "customer")
        user_ref.update({"role": new_role})

        log_action(
            payload.get("user_id"),
            payload.get("email"),
            role,
            "change_user_role",
            {"target_user_id": target_user_id, "old_role": old_role, "new_role": new_role}
        )

        return jsonify({"message": f"Role updated from {old_role} to {new_role}", "new_role": new_role}), 200

    except Exception as e:
        print(f"CHANGE USER ROLE ERROR: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500


def dashboard_stats(request, db, SECRET_KEY):
    try:
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

        # ---- Fetch all collections ----
        products_docs = db.collection("products").get()
        categories_docs = db.collection("categories").get()
        orders_docs = db.collection("orders").get()
        customers_docs = db.collection("customers").get()

        # ---- Products stats ----
        products = [doc.to_dict() for doc in products_docs]
        total_products = len(products)
        low_stock = sum(1 for p in products if 0 < (p.get("stock") or 0) <= 10)
        out_of_stock = sum(1 for p in products if (p.get("stock") or 0) == 0)
        total_stock = sum(p.get("stock") or 0 for p in products)
        total_value = sum((p.get("price") or 0) * (p.get("stock") or 0) for p in products)

        # ---- Products by category ----
        category_id_to_name = {}
        categories_list = []
        for doc in categories_docs:
            cat = doc.to_dict()
            cat_name = cat.get("name", "Unknown")
            category_id_to_name[doc.id] = cat_name
            sub_docs = doc.reference.collection("subcategories").get()
            categories_list.append({
                "category_id": doc.id,
                "name": cat_name,
                "subcategory_count": len(sub_docs)
            })

        product_count_by_cat = {}
        for p in products:
            cat_id = p.get("category_id", "")
            cat_name = category_id_to_name.get(cat_id, "Uncategorized")
            product_count_by_cat[cat_name] = product_count_by_cat.get(cat_name, 0) + 1

        products_by_category = [
            {"name": name, "count": count}
            for name, count in sorted(product_count_by_cat.items(), key=lambda x: x[1], reverse=True)
        ]

        categories_with_products = sum(1 for c in products_by_category if c["count"] > 0)

        # ---- Orders stats ----
        orders = []
        for doc in orders_docs:
            o = doc.to_dict()
            o["order_id"] = doc.id
            created = o.get("created_at")
            if created:
                o["created_at"] = created.isoformat() if hasattr(created, "isoformat") else str(created)
            orders.append(o)

        total_orders = len(orders)
        orders_by_status = {}
        for o in orders:
            status = o.get("status", "unknown")
            orders_by_status[status] = orders_by_status.get(status, 0) + 1

        total_revenue = sum(o.get("subtotal") or 0 for o in orders)

        recent_orders = sorted(orders, key=lambda x: x.get("created_at", ""), reverse=True)[:5]
        recent_orders_clean = []
        for o in recent_orders:
            recent_orders_clean.append({
                "order_id": o.get("order_id"),
                "customer_id": o.get("customer_id"),
                "subtotal": o.get("subtotal", 0),
                "status": o.get("status", "unknown"),
                "created_at": o.get("created_at", "")
            })

        # ---- Customers stats ----
        total_customers = len(customers_docs)

        # ---- Low stock products ----
        low_stock_products = sorted(
            [{"name": p.get("name", ""), "sku": p.get("sku", ""), "stock": p.get("stock", 0)}
             for p in products if 0 < (p.get("stock") or 0) <= 10],
            key=lambda x: x["stock"]
        )[:10]

        return jsonify({
            "products": {
                "total": total_products,
                "low_stock": low_stock,
                "out_of_stock": out_of_stock
            },
            "categories": {
                "total": len(categories_list),
                "with_products": categories_with_products
            },
            "orders": {
                "total": total_orders,
                "revenue": total_revenue,
                "by_status": orders_by_status
            },
            "customers": {
                "total": total_customers
            },
            "inventory": {
                "total_stock": total_stock,
                "total_value": total_value
            },
            "products_by_category": products_by_category,
            "recent_orders": recent_orders_clean,
            "low_stock_products": low_stock_products
        }), 200

    except Exception as e:
        print("DASHBOARD STATS ERROR:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# GET CUSTOMER PROFILE
# -----------------------------------------
def get_customer_profile(request, db, SECRET_KEY):
    try:
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

        user_id = payload.get("user_id")
        if not user_id:
            return jsonify({"error": "Invalid user token"}), 401

        user_doc = db.collection("users").document(user_id).get()
        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404

        user_data = user_doc.to_dict()
        profile = {
            "user_id": user_id,
            "name": user_data.get("name", ""),
            "email": user_data.get("email", ""),
            "phone": user_data.get("phone", ""),
            "location": user_data.get("location", ""),
            "role": user_data.get("role", "customer"),
            "created_at": user_data.get("created_at", ""),
        }

        return jsonify({"profile": profile}), 200

    except Exception as e:
        print("GET CUSTOMER PROFILE ERROR:", e)
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# UPDATE CUSTOMER PROFILE
# -----------------------------------------
def update_customer_profile(request, db, SECRET_KEY):
    try:
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

        user_id = payload.get("user_id")
        if not user_id:
            return jsonify({"error": "Invalid user token"}), 401

        data = request.get_json(silent=True) or {}

        allowed_fields = ["name", "phone", "location"]
        update_data = {}
        for field in allowed_fields:
            if field in data and data[field] is not None:
                update_data[field] = data[field]

        if not update_data:
            return jsonify({"error": "No valid fields to update"}), 400

        update_data["updated_at"] = firestore.SERVER_TIMESTAMP
        db.collection("users").document(user_id).update(update_data)

        log_action(user_id, payload.get("email"), payload.get("role", "customer"), "update_profile", {"fields": list(update_data.keys())})

        return jsonify({"message": "Profile updated successfully"}), 200

    except Exception as e:
        print("UPDATE CUSTOMER PROFILE ERROR:", e)
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# GET ALL BLOGS
# -----------------------------------------
def get_all_blogs(request, db):
    try:
        limit = request.args.get("limit", default=50, type=int)
        offset = request.args.get("offset", default=0, type=int)

        query = db.collection("blog_posts").order_by("created_at", direction=firestore.Query.DESCENDING)

        docs = list(query.stream())
        total = len(docs)
        paginated = docs[offset:offset + limit]

        blogs = []
        for doc in paginated:
            blog = doc.to_dict()
            blog["id"] = doc.id
            blogs.append(blog)

        return jsonify({"blogs": blogs, "total": total}), 200

    except Exception as e:
        print("GET ALL BLOGS ERROR:", e)
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# GET BLOG
# -----------------------------------------
def get_blog(request, db):
    try:
        blog_id = request.args.get("blog_id")
        if not blog_id:
            return jsonify({"error": "blog_id is required"}), 400

        doc = db.collection("blog_posts").document(blog_id).get()
        if not doc.exists:
            return jsonify({"error": "Blog post not found"}), 404

        blog = doc.to_dict()
        blog["id"] = doc.id

        return jsonify({"blog": blog}), 200

    except Exception as e:
        print("GET BLOG ERROR:", e)
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# CREATE BLOG (admin only)
# -----------------------------------------
def create_blog(request, db, SECRET_KEY):
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({"error": "Invalid token"}), 401

        role = payload.get("role", "")
        if role not in ["admin", "sub-admin", "super-admin"]:
            return jsonify({"error": "Admin access required"}), 403

        data = request.get_json(silent=True) or {}

        title = data.get("title", "").strip()
        if not title:
            return jsonify({"error": "Title is required"}), 400

        blog_data = {
            "title": title,
            "content": data.get("content", ""),
            "excerpt": data.get("excerpt", ""),
            "author": data.get("author", payload.get("email", "")),
            "image_url": data.get("image_url", ""),
            "tags": data.get("tags", []),
            "published": data.get("published", True),
            "created_at": firestore.SERVER_TIMESTAMP,
            "updated_at": firestore.SERVER_TIMESTAMP,
        }

        doc_ref = db.collection("blog_posts").add(blog_data)
        blog_id = doc_ref[1].id

        log_action(payload.get("user_id"), payload.get("email"), role, "create_blog", {"blog_id": blog_id, "title": title})

        return jsonify({"message": "Blog post created", "blog_id": blog_id}), 201

    except Exception as e:
        print("CREATE BLOG ERROR:", e)
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# SUBSCRIBE NEWSLETTER
# -----------------------------------------
def subscribe_newsletter(request, db):
    try:
        data = request.get_json(silent=True) or {}
        email = data.get("email", "").strip().lower()
        if not email:
            return jsonify({"error": "Email is required"}), 400

        # Check for duplicate
        existing = db.collection("newsletter_subscribers").where("email", "==", email).limit(1).stream()
        if any(True for _ in existing):
            return jsonify({"message": "Already subscribed"}), 200

        sub_data = {
            "email": email,
            "source": data.get("source", "website"),
            "subscribed_at": firestore.SERVER_TIMESTAMP,
        }

        db.collection("newsletter_subscribers").add(sub_data)

        return jsonify({"message": "Subscribed successfully"}), 201

    except Exception as e:
        print("SUBSCRIBE NEWSLETTER ERROR:", e)
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# SUBMIT CONTACT
# -----------------------------------------
def submit_contact(request, db):
    try:
        data = request.get_json(silent=True) or {}

        name = data.get("name", "").strip()
        email = data.get("email", "").strip()
        message = data.get("message", "").strip()

        if not name or not email or not message:
            return jsonify({"error": "Name, email, and message are required"}), 400

        contact_data = {
            "name": name,
            "email": email,
            "phone": data.get("phone", ""),
            "subject": data.get("subject", ""),
            "message": message,
            "status": "new",
            "created_at": firestore.SERVER_TIMESTAMP,
        }

        db.collection("contact_messages").add(contact_data)

        return jsonify({"message": "Contact message submitted successfully"}), 201

    except Exception as e:
        print("SUBMIT CONTACT ERROR:", e)
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# SUBMIT INQUIRY (authenticated)
# -----------------------------------------
def submit_inquiry(request, db, SECRET_KEY):
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({"error": "Invalid token"}), 401

        user_id = payload.get("user_id")
        data = request.get_json(silent=True) or {}

        inquiry_data = {
            "user_id": user_id,
            "email": data.get("email", payload.get("email", "")),
            "name": data.get("name", ""),
            "phone": data.get("phone", ""),
            "company": data.get("company", ""),
            "service_type": data.get("service_type", ""),
            "description": data.get("description", ""),
            "budget_range": data.get("budget_range", ""),
            "timeline": data.get("timeline", ""),
            "location": data.get("location", ""),
            "preferred_contact_method": data.get("preferred_contact_method", "email"),
            "cart_items": data.get("cart_items", []),
            "status": "pending",
            "created_at": firestore.SERVER_TIMESTAMP,
        }

        doc_ref = db.collection("service_inquiries").add(inquiry_data)
        inquiry_id = doc_ref[1].id

        log_action(user_id, payload.get("email"), payload.get("role", "customer"), "submit_inquiry", {"inquiry_id": inquiry_id})

        return jsonify({"message": "Inquiry submitted successfully", "inquiry_id": inquiry_id}), 201

    except Exception as e:
        print("SUBMIT INQUIRY ERROR:", e)
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# GET WISHLIST
# -----------------------------------------
def get_wishlist(request, db, SECRET_KEY):
    try:
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

        wishlist_ref = db.collection("customers").document(customer_id).collection("wishlist")
        wishlist_docs = list(wishlist_ref.stream())

        wishlist_items = []
        for doc in wishlist_docs:
            item = doc.to_dict()
            product_id = doc.id

            # Fetch product details
            product_doc = db.collection("products").document(product_id).get()
            if product_doc.exists:
                product_data = product_doc.to_dict()
                wishlist_items.append({
                    "product_id": product_id,
                    "name": product_data.get("name", ""),
                    "price": product_data.get("price", 0),
                    "images": product_data.get("images", []),
                    "sku": product_data.get("sku", ""),
                    "stock": product_data.get("stock", 0),
                    "added_at": item.get("added_at", ""),
                })

        return jsonify({"wishlist": wishlist_items}), 200

    except Exception as e:
        print("GET WISHLIST ERROR:", e)
        return jsonify({"error": str(e)}), 500


# -----------------------------------------
# APPLY COUPON
# -----------------------------------------
def apply_coupon(request, db, SECRET_KEY):
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({"error": "Invalid token"}), 401

        data = request.get_json(silent=True) or {}
        code = data.get("code", "").strip().upper()
        cart_total = data.get("cart_total", 0)

        if not code:
            return jsonify({"error": "Coupon code is required"}), 400

        # Look up coupon in discounts collection
        coupons = db.collection("discounts").where("code", "==", code).limit(1).stream()
        coupon_doc = None
        for doc in coupons:
            coupon_doc = doc
            break

        if not coupon_doc:
            return jsonify({"error": "Invalid coupon code"}), 404

        coupon = coupon_doc.to_dict()

        # Check if active
        if not coupon.get("active", False):
            return jsonify({"error": "This coupon is no longer active"}), 400

        # Check minimum order
        min_order = coupon.get("min_order", 0)
        if cart_total < min_order:
            return jsonify({"error": f"Minimum order of {min_order} required for this coupon"}), 400

        # Calculate discount
        discount_type = coupon.get("discount_type", "percentage")
        discount_value = coupon.get("discount_value", 0)

        if discount_type == "percentage":
            discount_amount = round(cart_total * (discount_value / 100), 2)
            max_discount = coupon.get("max_discount", None)
            if max_discount and discount_amount > max_discount:
                discount_amount = max_discount
        else:
            discount_amount = min(discount_value, cart_total)

        return jsonify({
            "valid": True,
            "code": code,
            "discount_type": discount_type,
            "discount_value": discount_value,
            "discount_amount": discount_amount,
            "new_total": round(cart_total - discount_amount, 2),
        }), 200

    except Exception as e:
        print("APPLY COUPON ERROR:", e)
        return jsonify({"error": str(e)}), 500

