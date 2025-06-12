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


@csrf_exempt
def login_api(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    try:
        data = json.loads(request.body.decode('utf-8'))
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return JsonResponse({'error': 'Missing username or password'}, status=400)

        with connection.cursor() as cursor:
            cursor.execute("SELECT password FROM users WHERE username = %s", [username])
            row = cursor.fetchone()
            if row is None:
                return JsonResponse({'error': 'Invalid username or password'}, status=401)

            hashed_password = row[0]

            if check_password(password, hashed_password):
                # Successful login
                return JsonResponse({'message': f'Logged in as {username}'}, status=200)
            else:
                return JsonResponse({'error': 'Invalid username or password'}, status=401)

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
        
        if not username or not email or not password or not mobile_no:
            return JsonResponse({'error': 'Missing required fields'}, status=400)
            
        # Check if verified user already exists
        with connection.cursor() as cursor:
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
        
        # Generate OTP
        otp = str(random.randint(100000, 999999))
        now = datetime.now()
        hashed_password = make_password(password)
        
        # Store temporary data in users table with is_verified=False
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO users 
                   (username, email, password, mobile_no, otp, otp_created_at, is_verified) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                [username, email, hashed_password, mobile_no, otp, now, False]
            )
            
        # Send OTP via email
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
            # Get search parameters
            search_query = request.GET.get('query', '').strip()
            category_id = request.GET.get('category_id')
            min_price = request.GET.get('min_price')
            max_price = request.GET.get('max_price')
            merchant_id = request.GET.get('merchant_id')
            sort_by = request.GET.get('sort_by', 'created_at')  # Default sort by creation date
            sort_order = request.GET.get('sort_order', 'desc')  # Default descending order
            page = int(request.GET.get('page', 1))
            per_page = int(request.GET.get('per_page', 10))

            # Validate sort parameters
            allowed_sort_fields = ['created_at', 'price', 'name', 'discount']
            if sort_by not in allowed_sort_fields:
                sort_by = 'created_at'

            if sort_order not in ['asc', 'desc']:
                sort_order = 'desc'

            # Calculate offset for pagination
            offset = (page - 1) * per_page

            with connection.cursor() as cursor:
                # Build the base query
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

                # Add search conditions
                if search_query:
                    query += " AND (LOWER(p.product_name) LIKE LOWER(%s) OR LOWER(p.description) LIKE LOWER(%s))"
                    search_pattern = f'%{search_query}%'
                    params.extend([search_pattern, search_pattern])

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

                # Add sorting
                query += f" ORDER BY p.{sort_by} {sort_order}"

                # Add pagination
                query += " LIMIT %s OFFSET %s"
                params.extend([per_page, offset])

                # Execute the query
                cursor.execute(query, params)
                columns = [col[0] for col in cursor.description]
                products = [dict(zip(columns, row)) for row in cursor.fetchall()]

                # Get total count for pagination
                count_query = """
                    SELECT COUNT(*)
                    FROM products p
                    JOIN categories c ON p.category_id = c.category_id
                    JOIN merchants m ON p.merchant_id = m.id
                    WHERE 1=1
                """
                count_params = []

                # Add the same search conditions to count query
                if search_query:
                    count_query += " AND (LOWER(p.product_name) LIKE LOWER(%s) OR LOWER(p.description) LIKE LOWER(%s))"
                    search_pattern = f'%{search_query}%'
                    count_params.extend([search_pattern, search_pattern])

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

                # Process the results
                for product in products:
                    product['images'] = json.loads(product['images'])

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
