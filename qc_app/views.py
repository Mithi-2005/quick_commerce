from django.shortcuts import render,redirect
from django.http import HttpResponse,JsonResponse
import json
from decouple import config
from django.db import connection 
from django.contrib import messages
from django.contrib.auth.hashers import make_password,check_password
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime
from django.utils.timezone import now as django_now
from datetime import timedelta
from django.core.mail import send_mail
import random
import string
import re


@csrf_exempt
def login_api(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    try:
        data = json.loads(request.body.decode('utf-8'))
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return JsonResponse({'error': 'Missing email or password'}, status=400)

        with connection.cursor() as cursor:
            cursor.execute("SELECT id, password FROM users WHERE email = %s", [email])
            row = cursor.fetchone()
            if row is None:
                return JsonResponse({'error': 'Invalid email or password'}, status=401)

            user_id, hashed_password = row

            if check_password(password, hashed_password):
                # Store user_id in session
                request.session['user_id'] = user_id
                # Successful login
                return JsonResponse({
                    'message': f'Logged in as {email}',
                    'user_id': user_id
                }, status=200)
            else:
                return JsonResponse({'error': 'Invalid email or password'}, status=401)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def signup_api(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)
    try:
        data = json.loads(request.body.decode('utf-8'))
        mobile_no = data.get('mobile_no')
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        referral_code_used = data.get('referral_code_used')
        
        if not username or not email or not password or not mobile_no:
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        
        otp = str(random.randint(100000, 999999))
        now = datetime.now()
        hashed_password = make_password(password)
        
        with connection.cursor() as cursor:
            # Check for existing user
            cursor.execute(
                "SELECT id FROM users WHERE (username = %s OR email = %s) AND is_verified = %s",
                [username, email, True]
            )
            if cursor.fetchone():
                return JsonResponse({'error': 'Username or email already exists'}, status=400)
            cursor.execute(
                "DELETE FROM users WHERE email = %s AND is_verified = %s",
                [email, False]
            )
            # Insert new user
            cursor.execute(
                """INSERT INTO users 
                   (username, email, password, mobile_no, otp, otp_created_at, is_verified, referral_code_used) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                [username, email, hashed_password, mobile_no, otp, now, False, referral_code_used]
            )
            user_id = cursor.lastrowid

            # Generate and insert referral code for this user
            referral_code = get_unique_referral_code(cursor)
            cursor.execute(
                "INSERT INTO referrals (user_id, referral_code, referred_user_ids, successful_referrals) VALUES (%s, %s, %s, %s)",
                [user_id, referral_code, json.dumps([]), json.dumps([])]
            )

            # If referral code was used, update referrer's referred_user_ids
            if referral_code_used:
                cursor.execute("SELECT user_id FROM referrals WHERE referral_code = %s", [referral_code_used])
                referrer = cursor.fetchone()
                if referrer:
                    referrer_id = referrer[0]
                    cursor.execute("SELECT referred_user_ids FROM referrals WHERE user_id = %s", [referrer_id])
                    referred_ids = cursor.fetchone()[0]
                    referred_list = json.loads(referred_ids) if referred_ids else []
                    referred_list.append(user_id)
                    cursor.execute("UPDATE referrals SET referred_user_ids = %s WHERE user_id = %s", [json.dumps(referred_list), referrer_id])

        send_otp_via_email(email, otp)
        return JsonResponse({
            'message': 'Signup initiated. Please verify your email with OTP.',
            'email': email
        }, status=201)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

def send_otp_via_email(email, otp):
    subject = "Your OTP Code"
    message = f"Your OTP is {otp}. It will expire in 5 minutes."
    from_email = 'ss.studysyn@gmail.com'
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list, fail_silently=False)

@csrf_exempt
def send_otp_api(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST allowed'}, status=405)
    try:
        data = json.loads(request.body.decode('utf-8'))
        email = data.get('email')

        if not email:
            return JsonResponse({'error': 'Mobile number is required'}, status=400)

        otp = str(random.randint(100000, 999999))
        now = datetime.now()

        with connection.cursor() as cursor:
            # Update OTP or create user entry (depends on your flow)
            cursor.execute(
                "UPDATE users SET otp = %s, otp_created_at = %s WHERE email = %s",
                [otp, now, email]
            )

        sms_response = send_otp_via_email(email, otp)

        return JsonResponse({'message': 'OTP sent successfully', 'otp': otp})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def resend_otp_api(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST allowed'}, status=405)
    try:
        data = json.loads(request.body.decode('utf-8'))
        email = data.get('email')

        if not email:
            return JsonResponse({'error': 'Email is required'}, status=400)

        with connection.cursor() as cursor:
            # Check if unverified user exists
            cursor.execute(
                "SELECT id FROM users WHERE email = %s AND is_verified = %s",
                [email, False]
            )
            if not cursor.fetchone():
                return JsonResponse({'error': 'No pending verification found for this email'}, status=404)

            # Generate new OTP
            otp = str(random.randint(100000, 999999))
            now = datetime.now()

            # Update OTP
            cursor.execute(
                "UPDATE users SET otp = %s, otp_created_at = %s WHERE email = %s AND is_verified = %s",
                [otp, now, email, False]
            )

        # Send new OTP
        send_otp_via_email(email, otp)

        return JsonResponse({
            'message': 'New OTP sent successfully',
            'email': email
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def verify_otp_api(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST allowed'}, status=405)

    try:
        data = json.loads(request.body.decode('utf-8'))
        email = data.get('email')
        otp_input = data.get('otp')

        if not email or not otp_input:
            return JsonResponse({'error': 'Email and OTP required'}, status=400)

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT otp, otp_created_at, is_verified FROM users WHERE email = %s AND is_verified = %s",
                [email, False]
            )
            row = cursor.fetchone()

            if not row:
                return JsonResponse({'error': 'No pending verification found for this email'}, status=404)

            db_otp, otp_time, is_verified = row

            if str(db_otp).strip() != str(otp_input).strip():
                return JsonResponse({'error': 'Invalid OTP'}, status=400)

            expiry_time = otp_time + timedelta(minutes=5)
            if datetime.now() > expiry_time:
                return JsonResponse({'error': 'OTP expired. Please request a new OTP'}, status=400)

            # Mark user as verified
            cursor.execute(
                "UPDATE users SET is_verified = %s WHERE email = %s",
                [True, email]
            )

            return JsonResponse({
                'message': 'Email verified successfully. You can now login.',
                'email': email
            }, status=200)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def get_product_by_id(request, product_id):
    if request.method == 'GET':
        try:
            with connection.cursor() as cursor:
                # Get product details with category and merchant information
                cursor.execute("""
                    SELECT 
                        p.product_id,
                        p.product_name,
                        p.description,
                        p.original_price,
                        p.discount,
                        p.final_price,
                        p.images,
                        p.stock,
                        p.category_id,
                        c.category_name,
                        p.merchant_id,
                        m.merchant_name,
                        m.store_name,
                        p.created_at
                    FROM products p
                    JOIN categories c ON p.category_id = c.category_id
                    JOIN merchants m ON p.merchant_id = m.id
                    WHERE p.product_id = %s
                """, [product_id])
                
                columns = [col[0] for col in cursor.description]
                result = cursor.fetchone()
                
                if not result:
                    return JsonResponse({'error': 'Product not found'}, status=404)
                
                product = dict(zip(columns, result))
                
                # Convert JSON string to list for images
                product['images'] = json.loads(product['images'])
                
                return JsonResponse({
                    'message': 'Product retrieved successfully',
                    'product': product
                })
                
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
            
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def get_products_by_category(request, category_id):
    if request.method == 'GET':
        try:
            # Get query parameters for pagination
            page = int(request.GET.get('page', 1))
            per_page = int(request.GET.get('per_page', 10))
            offset = (page - 1) * per_page

            with connection.cursor() as cursor:
                # Get total count
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM products 
                    WHERE category_id = %s
                """, [category_id])
                total_count = cursor.fetchone()[0]

                # Get products with pagination
                cursor.execute("""
                    SELECT p.*, c.category_name, m.merchant_name, m.store_name
                    FROM products p 
                    JOIN categories c ON p.category_id = c.category_id 
                    JOIN merchants m ON p.merchant_id = m.id
                    WHERE p.category_id = %s
                    ORDER BY p.created_at DESC
                    LIMIT %s OFFSET %s
                """, [category_id, per_page, offset])
                
                columns = [col[0] for col in cursor.description]
                products = cursor.fetchall()

                # Convert to list of dictionaries
                products_list = []
                for product in products:
                    product_dict = dict(zip(columns, product))
                    product_dict['images'] = json.loads(product_dict['images'])
                    products_list.append(product_dict)

                return JsonResponse({
                    'products': products_list,
                    'total': total_count,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': (total_count + per_page - 1) // per_page
                })

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def get_products_by_merchant(request, merchant_id):
    if request.method == 'GET':
        try:
            # Get query parameters for pagination
            page = int(request.GET.get('page', 1))
            per_page = int(request.GET.get('per_page', 10))
            offset = (page - 1) * per_page

            with connection.cursor() as cursor:
                # Get total count
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM products 
                    WHERE merchant_id = %s
                """, [merchant_id])
                total_count = cursor.fetchone()[0]

                cursor.execute("""
                    SELECT p.*, c.category_name, m.merchant_name, m.store_name
                    FROM products p 
                    JOIN categories c ON p.category_id = c.category_id 
                    JOIN merchants m ON p.merchant_id = m.id
                    WHERE p.merchant_id = %s
                    ORDER BY p.created_at DESC
                    LIMIT %s OFFSET %s
                """, [merchant_id, per_page, offset])
                
                columns = [col[0] for col in cursor.description]
                products = cursor.fetchall()

                # Convert to list of dictionaries
                products_list = []
                for product in products:
                    product_dict = dict(zip(columns, product))
                    product_dict['images'] = json.loads(product_dict['images'])
                    products_list.append(product_dict)

                return JsonResponse({
                    'products': products_list,
                    'total': total_count,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': (total_count + per_page - 1) // per_page
                })

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def search_products(request):
    if request.method == 'GET':
        try:
            # Get and clean search query
            raw_query = request.GET.get('query', '').strip()
            search_lower = raw_query.lower()

            # Extract min and max price from query string
            min_price = request.GET.get('min_price')
            max_price = request.GET.get('max_price')

            # Detect and parse price keywords in raw_query
            match = re.search(r'between\s+(\d+)\s+and\s+(\d+)', search_lower)
            if match:
                min_price = min_price or match.group(1)
                max_price = max_price or match.group(2)
                search_lower = search_lower.replace(match.group(0), '')

            match = re.search(r'(under|below|less than)\s+(\d+)', search_lower)
            if match:
                max_price = max_price or match.group(2)
                search_lower = search_lower.replace(match.group(0), '')

            match = re.search(r'(above|over|greater than)\s+(\d+)', search_lower)
            if match:
                min_price = min_price or match.group(2)
                search_lower = search_lower.replace(match.group(0), '')

            # Clean remaining search query
            search_query = re.sub(r'\s+', ' ', search_lower).strip()

            # Additional filters
            category_id = request.GET.get('category_id')
            merchant_id = request.GET.get('merchant_id')
            sort_by = request.GET.get('sort_by', 'created_at')
            sort_order = request.GET.get('sort_order', 'desc')
            page = int(request.GET.get('page', 1))
            per_page = int(request.GET.get('per_page', 10))

            allowed_sort_fields = ['created_at', 'price', 'name', 'discount']
            if sort_by not in allowed_sort_fields:
                sort_by = 'created_at'
            if sort_order not in ['asc', 'desc']:
                sort_order = 'desc'

            offset = (page - 1) * per_page

            with connection.cursor() as cursor:
                # Build main product query
                query = """
                    SELECT 
                        p.product_id,
                        p.product_name,
                        p.description,
                        p.original_price,
                        p.discount,
                        p.final_price,
                        p.images,
                        p.stock,
                        p.category_id,
                        c.category_name,
                        p.merchant_id,
                        m.merchant_name,
                        m.store_name,
                        p.created_at
                    FROM products p
                    JOIN categories c ON p.category_id = c.category_id
                    JOIN merchants m ON p.merchant_id = m.id
                    WHERE 1=1
                """
                params = []

                # Apply keyword search
                if search_query:
                    query += """
                        AND (
                            LOWER(p.product_name) LIKE LOWER(%s)
                            OR LOWER(p.description) LIKE LOWER(%s)
                            OR LOWER(c.category_name) LIKE LOWER(%s)
                        )
                    """
                    like_pattern = f"%{search_query}%"
                    params.extend([like_pattern, like_pattern, like_pattern])

                # Apply filters
                if category_id:
                    query += " AND p.category_id = %s"
                    params.append(category_id)

                if min_price:
                    query += " AND p.final_price >= %s"
                    params.append(float(min_price))

                if max_price:
                    query += " AND p.final_price <= %s"
                    params.append(float(max_price))

                if merchant_id:
                    query += " AND p.merchant_id = %s"
                    params.append(merchant_id)

                # Sorting and pagination
                query += f" ORDER BY p.{sort_by} {sort_order}"
                query += " LIMIT %s OFFSET %s"
                params.extend([per_page, offset])

                cursor.execute(query, params)
                columns = [col[0] for col in cursor.description]
                products = [dict(zip(columns, row)) for row in cursor.fetchall()]

                # Build count query
                count_query = """
                    SELECT COUNT(*)
                    FROM products p
                    JOIN categories c ON p.category_id = c.category_id
                    JOIN merchants m ON p.merchant_id = m.id
                    WHERE 1=1
                """
                count_params = []

                if search_query:
                    count_query += """
                        AND (
                            LOWER(p.product_name) LIKE LOWER(%s)
                            OR LOWER(p.description) LIKE LOWER(%s)
                            OR LOWER(c.category_name) LIKE LOWER(%s)
                        )
                    """
                    count_params.extend([like_pattern, like_pattern, like_pattern])

                if category_id:
                    count_query += " AND p.category_id = %s"
                    count_params.append(category_id)

                if min_price:
                    count_query += " AND p.final_price >= %s"
                    count_params.append(float(min_price))

                if max_price:
                    count_query += " AND p.final_price <= %s"
                    count_params.append(float(max_price))

                if merchant_id:
                    count_query += " AND p.merchant_id = %s"
                    count_params.append(merchant_id)

                cursor.execute(count_query, count_params)
                total_count = cursor.fetchone()[0]

                # Format product images
                for product in products:
                    try:
                        product['images'] = json.loads(product['images'])
                    except:
                        product['images'] = []

                return JsonResponse({
                    'message': 'Products retrieved successfully',
                    'products': products,
                    'pagination': {
                        'total': total_count,
                        'page': page,
                        'per_page': per_page,
                        'total_pages': (total_count + per_page - 1) // per_page
                    }
                })

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def add_address(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)
    
    try:
        # Check if user is logged in via session
        if 'user_id' not in request.session:
            return JsonResponse({'error': 'User not authenticated'}, status=401)

        user_id = request.session['user_id']
        data = json.loads(request.body.decode('utf-8'))
        
        full_name = data.get('full_name')
        phone_number = data.get('phone_number')
        address_line1 = data.get('address_line1')
        address_line2 = data.get('address_line2')
        city = data.get('city')
        state = data.get('state')
        postal_code = data.get('postal_code')
        country = data.get('country')
        is_default = data.get('is_default', False)

        # Validate required fields
        required_fields = ['full_name', 'phone_number', 'address_line1', 'city', 'state', 'postal_code', 'country']
        for field in required_fields:
            if not data.get(field):
                return JsonResponse({'error': f'{field} is required'}, status=400)

        with connection.cursor() as cursor:
            # Verify user exists
            cursor.execute("SELECT id FROM users WHERE id = %s", [user_id])
            if not cursor.fetchone():
                return JsonResponse({'error': 'User not found'}, status=404)

            # If this is set as default, unset any existing default address
            if is_default:
                cursor.execute(
                    "UPDATE user_addresses SET is_default = FALSE WHERE user_id = %s",
                    [user_id]
                )

            # Insert new address
            cursor.execute("""
                INSERT INTO user_addresses 
                (user_id, full_name, phone_number, address_line1, address_line2, 
                city, state, postal_code, country, is_default)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, [user_id, full_name, phone_number, address_line1, address_line2, 
                 city, state, postal_code, country, is_default])

        return JsonResponse({'message': 'Address added successfully'}, status=201)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def edit_address(request, address_id):
    if request.method != 'PUT':
        return JsonResponse({'error': 'Only PUT method allowed'}, status=405)
    
    try:
        data = json.loads(request.body.decode('utf-8'))
        full_name = data.get('full_name')
        phone_number = data.get('phone_number')
        address_line1 = data.get('address_line1')
        address_line2 = data.get('address_line2')
        city = data.get('city')
        state = data.get('state')
        postal_code = data.get('postal_code')
        country = data.get('country')
        is_default = data.get('is_default')

        # Validate required fields
        required_fields = ['full_name', 'phone_number', 'address_line1', 'city', 'state', 'postal_code', 'country']
        for field in required_fields:
            if not data.get(field):
                return JsonResponse({'error': f'{field} is required'}, status=400)

        with connection.cursor() as cursor:
            # Get user_id for this address
            cursor.execute("SELECT user_id FROM user_addresses WHERE id = %s", [address_id])
            result = cursor.fetchone()
            if not result:
                return JsonResponse({'error': 'Address not found'}, status=404)
            
            user_id = result[0]

            # If this is set as default, unset any existing default address
            if not is_default:
                is_default = False

            # Update address
            cursor.execute("""
                UPDATE user_addresses 
                SET full_name = %s, phone_number = %s, address_line1 = %s, 
                    address_line2 = %s, city = %s, state = %s, 
                    postal_code = %s, country = %s, is_default = %s
                WHERE id = %s
            """, [full_name, phone_number, address_line1, address_line2, 
                 city, state, postal_code, country, is_default, address_id])

        return JsonResponse({'message': 'Address updated successfully'})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def delete_address(request, address_id):
    if request.method != 'DELETE':
        return JsonResponse({'error': 'Only DELETE method allowed'}, status=405)
    
    try:
        with connection.cursor() as cursor:
            # Check if address exists
            cursor.execute("SELECT id FROM user_addresses WHERE id = %s", [address_id])
            if not cursor.fetchone():
                return JsonResponse({'error': 'Address not found'}, status=404)

            # Delete address
            cursor.execute("DELETE FROM user_addresses WHERE id = %s", [address_id])

        return JsonResponse({'message': 'Address deleted successfully'})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def get_user_addresses(request, user_id):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET method allowed'}, status=405)
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id, full_name, phone_number, address_line1, address_line2,
                       city, state, postal_code, country, is_default
                FROM user_addresses
                WHERE user_id = %s
                ORDER BY is_default DESC, id DESC
            """, [user_id])
            
            columns = [col[0] for col in cursor.description]
            addresses = []
            for row in cursor.fetchall():
                address = dict(zip(columns, row))
                addresses.append(address)

        return JsonResponse({'addresses': addresses})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def get_address_by_id(request, address_id):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET method allowed'}, status=405)
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id, user_id, full_name, phone_number, address_line1, address_line2,
                       city, state, postal_code, country, is_default
                FROM user_addresses
                WHERE id = %s
            """, [address_id])
            
            row = cursor.fetchone()
            if not row:
                return JsonResponse({'error': 'Address not found'}, status=404)
            
            columns = [col[0] for col in cursor.description]
            address = dict(zip(columns, row))

        return JsonResponse({'address': address})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def add_to_cart(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)
    
    try:
        data = json.loads(request.body.decode('utf-8'))
        user_id = request.session.get('user_id')
        if not user_id:
            return JsonResponse({'error': 'User not authenticated'}, status=401)

        product_id = data.get('product_id')
        quantity = data.get('quantity', 1)

        if not product_id:
            return JsonResponse({'error': 'Product ID is required'}, status=400)

        with connection.cursor() as cursor:
            # Get or create cart
            cursor.execute("SELECT cart_id FROM cart WHERE user_id = %s", [user_id])
            cart = cursor.fetchone()
            
            if not cart:
                cursor.execute("INSERT INTO cart (user_id) VALUES (%s)", [user_id])
                cart_id = cursor.lastrowid
            else:
                cart_id = cart[0]

            # Check if product already in cart
            cursor.execute("""
                SELECT id, quantity FROM cart_items 
                WHERE cart_id = %s AND product_id = %s
            """, [cart_id, product_id])
            
            existing_item = cursor.fetchone()
            
            if existing_item:
                # Update quantity
                new_quantity = existing_item[1] + quantity
                cursor.execute("""
                    UPDATE cart_items 
                    SET quantity = %s 
                    WHERE id = %s
                """, [new_quantity, existing_item[0]])
            else:
                # Add new item
                cursor.execute("""
                    INSERT INTO cart_items (cart_id, product_id, quantity)
                    VALUES (%s, %s, %s)
                """, [cart_id, product_id, quantity])

        return JsonResponse({'message': 'Item added to cart successfully'}, status=201)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def get_cart(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET method allowed'}, status=405)
    
    try:
        user_id = request.session.get('user_id')
        if not user_id:
            return JsonResponse({'error': 'User not authenticated'}, status=401)

        with connection.cursor() as cursor:
            # Get cart items with product details
            cursor.execute("""
                SELECT ci.id, ci.product_id, ci.quantity, ci.added_at,
                       p.product_name, p.original_price, p.final_price, p.images,
                       m.merchant_name as merchant_name
                FROM cart c
                JOIN cart_items ci ON c.cart_id = ci.cart_id
                JOIN products p ON ci.product_id = p.product_id
                JOIN merchants m ON p.merchant_id = m.id
                WHERE c.user_id = %s
            """, [user_id])
            
            columns = [col[0] for col in cursor.description]
            items = []
            total_amount = 0
            
            for row in cursor.fetchall():
                item = dict(zip(columns, row))
                item['final_price'] = item['final_price']
                item['subtotal'] = item['final_price'] * item['quantity']
                total_amount += item['subtotal']
                items.append(item)

        return JsonResponse({
            'items': items,
            'total_amount': total_amount
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def update_cart_item(request, item_id):
    if request.method != 'PUT':
        print(request.method)
        return JsonResponse({'error': 'Only PUT method allowed'}, status=405)
    
    try:
        data = json.loads(request.body.decode('utf-8'))
        quantity = data.get('quantity')
        
        if not quantity or quantity < 1:
            return JsonResponse({'error': 'Valid quantity is required'}, status=400)

        user_id = request.session.get('user_id')
        if not user_id:
            return JsonResponse({'error': 'User not authenticated'}, status=401)

        with connection.cursor() as cursor:
            # Verify cart item belongs to user
            cursor.execute("""
                SELECT ci.id FROM cart_items ci
                JOIN cart c ON ci.cart_id = c.cart_id
                WHERE ci.id = %s AND c.user_id = %s
            """, [item_id, user_id])
            
            if not cursor.fetchone():
                return JsonResponse({'error': 'Cart item not found'}, status=404)

            # Update quantity
            cursor.execute("""
                UPDATE cart_items 
                SET quantity = %s 
                WHERE id = %s
            """, [quantity, item_id])

        return JsonResponse({'message': 'Cart item updated successfully'})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def remove_from_cart(request, item_id):
    if request.method != 'DELETE':
        return JsonResponse({'error': 'Only DELETE method allowed'}, status=405)
    
    try:
        user_id = request.session.get('user_id')
        if not user_id:
            return JsonResponse({'error': 'User not authenticated'}, status=401)

        with connection.cursor() as cursor:
            # Verify cart item belongs to user
            cursor.execute("""
                SELECT ci.id FROM cart_items ci
                JOIN cart c ON ci.cart_id = c.cart_id
                WHERE ci.id = %s AND c.user_id = %s
            """, [item_id, user_id])
            
            if not cursor.fetchone():
                return JsonResponse({'error': 'Cart item not found'}, status=404)

            # Delete item
            cursor.execute("DELETE FROM cart_items WHERE id = %s", [item_id])

        return JsonResponse({'message': 'Item removed from cart successfully'})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def place_order(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)
    
    try:
        data = json.loads(request.body.decode('utf-8'))
        user_id = request.session.get('user_id')
        if not user_id:
            return JsonResponse({'error': 'User not authenticated'}, status=401)

        address_id = data.get('address_id')
        if not address_id:
            return JsonResponse({'error': 'Address ID is required'}, status=400)

        with connection.cursor() as cursor:
            # Start transaction
            cursor.execute("START TRANSACTION")

            try:
                # Get cart items with product details
                cursor.execute("""
                    SELECT ci.product_id, ci.quantity, p.original_price, p.final_price,
                           p.merchant_id, p.stock
                    FROM cart c
                    JOIN cart_items ci ON c.cart_id = ci.cart_id
                    JOIN products p ON ci.product_id = p.product_id
                    WHERE c.user_id = %s
                """, [user_id])
                
                cart_items = cursor.fetchall()
                if not cart_items:
                    raise Exception('Cart is empty')

                # Check stock availability and calculate total amount
                total_amount = 0
                for item in cart_items:
                    product_id, quantity, price, discount_price, merchant_id, stock = item
                    if quantity > stock:
                        raise Exception(f'Insufficient stock for product ID {product_id}')
                    final_price = discount_price or price
                    total_amount += final_price * quantity

                # Create order
                cursor.execute("""
                    INSERT INTO orders (user_id, address_id, total_amount, payment_mode, payment_status)
                    VALUES (%s, %s, %s, %s, %s)
                """, [user_id, address_id, total_amount, 'COD', 'pending'])
                
                order_id = cursor.lastrowid

                # Create order items and update stock
                for item in cart_items:
                    product_id, quantity, price, discount_price, merchant_id, stock = item
                    final_price = discount_price or price
                    
                    # Create order item
                    cursor.execute("""
                        INSERT INTO order_items 
                        (order_id, product_id, merchant_id, quantity, price, final_price, status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, [order_id, product_id, merchant_id, quantity, price, final_price, 'placed'])

                    # Update product stock
                    cursor.execute("""
                        UPDATE products 
                        SET stock = stock - %s 
                        WHERE product_id = %s
                    """, [quantity, product_id])

                # Clear cart
                cursor.execute("""
                    DELETE ci FROM cart_items ci
                    JOIN cart c ON ci.cart_id = c.cart_id
                    WHERE c.user_id = %s
                """, [user_id])

                # After order is placed, check if this is the user's first order
                cursor.execute("SELECT COUNT(*) FROM orders WHERE user_id = %s", [user_id])
                order_count = cursor.fetchone()[0]
                if order_count == 1:
                    # Check if user was referred
                    cursor.execute("SELECT referral_code_used FROM users WHERE id = %s", [user_id])
                    code_used = cursor.fetchone()[0]
                    if code_used:
                        cursor.execute("SELECT user_id FROM referrals WHERE referral_code = %s", [code_used])
                        referrer = cursor.fetchone()
                        if referrer:
                            referrer_id = referrer[0]
                            # Add 50 points to referrer
                            cursor.execute("SELECT total_points, history FROM points WHERE user_id = %s", [referrer_id])
                            row = cursor.fetchone()
                            if row:
                                total_points, history = row
                                total_points += 50
                                history_list = json.loads(history) if history else []
                                history_list.append({"source": "referral", "points": 50, "date": datetime.now().strftime("%Y-%m-%d")})
                                cursor.execute("UPDATE points SET total_points = %s, history = %s WHERE user_id = %s", [total_points, json.dumps(history_list), referrer_id])
                            else:
                                history_list = [{"source": "referral", "points": 50, "date": datetime.now().strftime("%Y-%m-%d")}]
                                cursor.execute("INSERT INTO points (user_id, total_points, history) VALUES (%s, %s, %s)", [referrer_id, 50, json.dumps(history_list)])
                            # Update successful_referrals
                            cursor.execute("SELECT successful_referrals FROM referrals WHERE user_id = %s", [referrer_id])
                            succ_ref = cursor.fetchone()[0]
                            succ_list = json.loads(succ_ref) if succ_ref else []
                            succ_list.append(user_id)
                            cursor.execute("UPDATE referrals SET successful_referrals = %s WHERE user_id = %s", [json.dumps(succ_list), referrer_id])

                cursor.execute("COMMIT")
                return JsonResponse({
                    'message': 'Order placed successfully',
                    'order_id': order_id,
                    'total_amount': total_amount
                }, status=201)

            except Exception as e:
                cursor.execute("ROLLBACK")
                raise e

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def get_orders(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET method allowed'}, status=405)
    
    try:
        user_id = request.session.get('user_id')
        if not user_id:
            return JsonResponse({'error': 'User not authenticated'}, status=401)

        with connection.cursor() as cursor:
            # Get orders with address details
            cursor.execute("""
                SELECT o.order_id, o.total_amount, o.payment_mode, o.payment_status,
                       o.created_at, a.full_name, a.phone_number, a.address_line1,
                       a.address_line2, a.city, a.state, a.postal_code, a.country
                FROM orders o
                LEFT JOIN user_addresses a ON o.address_id = a.id
                WHERE o.user_id = %s
                ORDER BY o.created_at DESC
            """, [user_id])
            
            columns = [col[0] for col in cursor.description]
            orders = []
            
            for row in cursor.fetchall():
                order = dict(zip(columns, row))
                
                # Get order items
                cursor.execute("""
                    SELECT oi.id, oi.product_id, oi.quantity, oi.price, oi.final_price,
                           oi.status, p.product_name, p.images, m.merchant_name as merchant_name
                    FROM order_items oi
                    JOIN products p ON oi.product_id = p.product_id
                    JOIN merchants m ON oi.merchant_id = m.id
                    WHERE oi.order_id = %s
                """, [order['order_id']])
                
                item_columns = [col[0] for col in cursor.description]
                order['items'] = [dict(zip(item_columns, item)) for item in cursor.fetchall()]
                orders.append(order)

        return JsonResponse({'orders': orders})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

def generate_referral_code():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=6))

def get_unique_referral_code(cursor):
    while True:
        code = generate_referral_code()
        cursor.execute("SELECT 1 FROM referrals WHERE referral_code = %s", [code])
        if not cursor.fetchone():
            return code

@csrf_exempt
def get_referral_code(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET method allowed'}, status=405)
    user_id = request.session.get('user_id')
    if not user_id:
        return JsonResponse({'error': 'User not authenticated'}, status=401)
    with connection.cursor() as cursor:
        cursor.execute("SELECT referral_code FROM referrals WHERE user_id = %s", [user_id])
        row = cursor.fetchone()
        if not row:
            return JsonResponse({'error': 'Referral code not found'}, status=404)
        return JsonResponse({'referral_code': row[0]})

@csrf_exempt
def get_referrals(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET method allowed'}, status=405)
    user_id = request.session.get('user_id')
    if not user_id:
        return JsonResponse({'error': 'User not authenticated'}, status=401)
    with connection.cursor() as cursor:
        cursor.execute("SELECT referred_user_ids, successful_referrals FROM referrals WHERE user_id = %s", [user_id])
        row = cursor.fetchone()
        if not row:
            return JsonResponse({'error': 'Referral info not found'}, status=404)
        referred = json.loads(row[0]) if row[0] else []
        successful = set(json.loads(row[1]) if row[1] else [])
        referred_details = []
        if referred:
            format_strings = ','.join(['%s'] * len(referred))
            cursor.execute(f"SELECT id, username FROM users WHERE id IN ({format_strings})", referred)
            user_map = {r[0]: r[1] for r in cursor.fetchall()}
            for rid in referred:
                referred_details.append({
                    'user_id': rid,
                    'username': user_map.get(rid, ''),
                    'points_earned': 50 if rid in successful else 0
                })
        return JsonResponse({'referred': referred_details})

@csrf_exempt
def get_points_history(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET method allowed'}, status=405)
    user_id = request.session.get('user_id')
    if not user_id:
        return JsonResponse({'error': 'User not authenticated'}, status=401)
    with connection.cursor() as cursor:
        cursor.execute("SELECT total_points, history FROM points WHERE user_id = %s", [user_id])
        row = cursor.fetchone()
        if not row:
            return JsonResponse({'total_points': 0, 'history': []})
        total_points, history = row
        history_list = json.loads(history) if history else []
        return JsonResponse({'total_points': total_points, 'history': history_list})

@csrf_exempt
def get_user_details(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET method allowed'}, status=405)
    user_id = request.session.get('user_id')
    if not user_id:
        return JsonResponse({'error': 'User not authenticated'}, status=401)
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, username, email, mobile_no, is_verified, referral_code_used FROM users WHERE id = %s", [user_id])
        row = cursor.fetchone()
        if not row:
            return JsonResponse({'error': 'User not found'}, status=404)
        columns = [col[0] for col in cursor.description]
        user = dict(zip(columns, row))
        # Add referral code
        cursor.execute("SELECT referral_code FROM referrals WHERE user_id = %s", [user_id])
        ref_row = cursor.fetchone()
        user['referral_code'] = ref_row[0] if ref_row else None
        # Add points
        cursor.execute("SELECT total_points FROM points WHERE user_id = %s", [user_id])
        points_row = cursor.fetchone()
        user['total_points'] = points_row[0] if points_row else 0
        return JsonResponse({'user': user})
