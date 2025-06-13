from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import send_mail
from django.conf import settings
from .utils import upload_file_to_s3
import json
import random
import string
from datetime import datetime, timedelta


otp_store = {}

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    subject = 'Verify your merchant account'
    message = f'Your OTP for merchant account verification is: {otp}\nThis OTP is valid for 10 minutes.'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]
    
    try:
        send_mail(subject, message, from_email, recipient_list)
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

@csrf_exempt
def send_verification_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')

            if not email:
                return JsonResponse({'error': 'Email is required'}, status=400)

            # Check if email already exists
            with connection.cursor() as cursor:
                cursor.execute("SELECT id FROM merchants WHERE email = %s", [email])
                if cursor.fetchone():
                    return JsonResponse({'error': 'Email already registered'}, status=400)

            # Generate and store OTP
            otp = generate_otp()
            otp_store[email] = {
                'otp': otp,
                'created_at': datetime.now(),
                'verified': False
            }
            
            if send_otp_email(email, otp):
                return JsonResponse({'message': 'OTP sent successfully'})
            else:
                return JsonResponse({'error': 'Failed to send OTP'}, status=500)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def verify_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            otp = data.get('otp')

            if not email or not otp:
                return JsonResponse({'error': 'Email and OTP are required'}, status=400)

            # Check if OTP exists and is valid
            if email not in otp_store:
                return JsonResponse({'error': 'OTP not found or expired'}, status=400)

            stored_data = otp_store[email]
            if datetime.now() - stored_data['created_at'] > timedelta(minutes=10):
                del otp_store[email]
                return JsonResponse({'error': 'OTP expired'}, status=400)

            if stored_data['otp'] != otp:
                return JsonResponse({'error': 'Invalid OTP'}, status=400)

            # Mark email as verified
            otp_store[email]['verified'] = True
            return JsonResponse({'message': 'OTP verified successfully'})

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def merchant_signup(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            merchant_name = data.get('merchant_name')
            store_name = data.get('store_name')
            mobile_no = data.get('mobile_no')
            street = data.get('street')
            city = data.get('city')
            state = data.get('state')
            country = data.get('country')
            email = data.get('email')
            password = data.get('password')

            # Validate required fields
            if not all([merchant_name, store_name, mobile_no, email, password]):
                return JsonResponse({'error': 'All required fields must be filled'}, status=400)

            # Check if email is verified
            if email not in otp_store or not otp_store[email]['verified']:
                return JsonResponse({'error': 'Email not verified'}, status=400)

            # Hash the password
            hashed_password = make_password(password)

            with connection.cursor() as cursor:
                # Insert new merchant
                cursor.execute("""
                    INSERT INTO merchants (
                        merchant_name, store_name, mobile_no, street, 
                        city, state, country, email, password
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, [
                    merchant_name, store_name, mobile_no, street,
                    city, state, country, email, hashed_password
                ])

            # Clean up OTP data
            del otp_store[email]

            return JsonResponse({'message': 'Merchant registered successfully'}, status=201)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def merchant_login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')

            if not email or not password:
                return JsonResponse({'error': 'Email and password are required'}, status=400)

            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT id, merchant_name, store_name, email, password 
                    FROM merchants WHERE email = %s
                """, [email])
                
                merchant = cursor.fetchone()

                if not merchant:
                    return JsonResponse({'error': 'Invalid credentials'}, status=401)

                merchant_id, merchant_name, store_name, merchant_email, hashed_password = merchant

                if not check_password(password, hashed_password):
                    return JsonResponse({'error': 'Invalid credentials'}, status=401)

                # Store merchant info in session
                request.session['merchant_id'] = merchant_id
                request.session['merchant_name'] = merchant_name
                request.session['store_name'] = store_name
                request.session['email'] = merchant_email

                return JsonResponse({
                    'message': 'Login successful',
                    'merchant': {
                        'id': merchant_id,
                        'merchant_name': merchant_name,
                        'store_name': store_name,
                        'email': merchant_email
                    }
                })

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def merchant_logout(request):
    if request.method == 'POST':
        request.session.flush()
        return JsonResponse({'message': 'Logged out successfully'})
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def upload_product_image(request):
    if request.method == 'POST':
        try:
            # Check if merchant is logged in
            if 'merchant_id' not in request.session:
                return JsonResponse({'error': 'Authentication required'}, status=401)

            # Check if file is present in request
            if 'image' not in request.FILES:
                return JsonResponse({'error': 'No image file provided'}, status=400)

            image_file = request.FILES['image']
            
            # Validate file type
            allowed_types = ['image/jpeg', 'image/png', 'image/jpg']
            if image_file.content_type not in allowed_types:
                return JsonResponse({'error': 'Invalid file type. Only JPEG and PNG are allowed'}, status=400)

            # Validate file size (max 5MB)
            if image_file.size > 5 * 1024 * 1024:
                return JsonResponse({'error': 'File size too large. Maximum size is 5MB'}, status=400)

            # Upload to S3
            image_url = upload_file_to_s3(image_file)

            return JsonResponse({
                'message': 'Image uploaded successfully',
                'image_url': image_url
            })

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def add_product(request):
    if request.method == 'POST':
        try:
            # Check if merchant is logged in
            if 'merchant_id' not in request.session:
                return JsonResponse({'error': 'Authentication required'}, status=401)

            merchant_id = request.session['merchant_id']
            
            # Handle multipart form data
            product_name = request.POST.get('product_name')
            description = request.POST.get('description')
            original_price = request.POST.get('original_price')
            discount = request.POST.get('discount', 0.00)
            stock = request.POST.get('stock', 0)
            category_id = request.POST.get('category_id')
            
            # Get all uploaded images
            image_files = request.FILES.getlist('images')
            uploaded_urls = []

            # Validate required fields
            if not all([product_name, original_price, category_id]):
                return JsonResponse({'error': 'Product name, price, and category are required'}, status=400)

            # Validate and upload images
            for image_file in image_files:
                # Validate file type
                allowed_types = ['image/jpeg', 'image/png', 'image/jpg']
                if image_file.content_type not in allowed_types:
                    continue  # Skip invalid files

                # Validate file size (max 5MB)
                if image_file.size > 5 * 1024 * 1024:
                    continue  # Skip large files

                # Upload to S3
                image_url = upload_file_to_s3(image_file)
                uploaded_urls.append(image_url)

            if not uploaded_urls:
                return JsonResponse({'error': 'At least one valid image is required'}, status=400)

            # Calculate final price
            final_price=request.POST.get('final_price')

            with connection.cursor() as cursor:
                # Check if category exists
                cursor.execute("SELECT category_id FROM categories WHERE category_id = %s", [category_id])
                if not cursor.fetchone():
                    return JsonResponse({'error': 'Invalid category'}, status=400)

                # Insert product
                cursor.execute("""
                    INSERT INTO products (
                        merchant_id, product_name, description, original_price,
                        discount, final_price, images, stock, category_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, [
                    merchant_id, product_name, description, original_price,
                    discount, final_price, json.dumps(uploaded_urls), stock, category_id
                ])

                # Get the inserted product ID
                product_id = cursor.lastrowid

                # Get the inserted product details
                cursor.execute("""
                    SELECT p.*, c.category_name 
                    FROM products p 
                    JOIN categories c ON p.category_id = c.category_id 
                    WHERE p.product_id = %s
                """, [product_id])
                
                columns = [col[0] for col in cursor.description]
                product = dict(zip(columns, cursor.fetchone()))

                # Convert JSON string to list for images
                product['images'] = json.loads(product['images'])

            return JsonResponse({
                'message': 'Product added successfully',
                'product': product
            }, status=201)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def upload_product_images(request):
    if request.method == 'POST':
        try:
            # Check if merchant is logged in
            if 'merchant_id' not in request.session:
                return JsonResponse({'error': 'Authentication required'}, status=401)

            # Check if files are present in request
            if 'images' not in request.FILES:
                return JsonResponse({'error': 'No images provided'}, status=400)

            image_files = request.FILES.getlist('images')
            uploaded_urls = []

            # Validate and upload each image
            for image_file in image_files:
                # Validate file type
                allowed_types = ['image/jpeg', 'image/png', 'image/jpg']
                if image_file.content_type not in allowed_types:
                    continue  # Skip invalid files

                # Validate file size (max 5MB)
                if image_file.size > 5 * 1024 * 1024:
                    continue  # Skip large files

                # Upload to S3
                image_url = upload_file_to_s3(image_file)
                uploaded_urls.append(image_url)

            if not uploaded_urls:
                return JsonResponse({'error': 'No valid images were uploaded'}, status=400)

            return JsonResponse({
                'message': 'Images uploaded successfully',
                'image_urls': uploaded_urls
            })

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def edit_product(request, product_id):
    if request.method == 'POST':
        try:
            # Check if merchant is logged in
            if 'merchant_id' not in request.session:
                return JsonResponse({'error': 'Authentication required'}, status=401)

            merchant_id = request.session['merchant_id']
            
            # First verify if the product belongs to this merchant
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT merchant_id, images 
                    FROM products 
                    WHERE product_id = %s
                """, [product_id])
                result = cursor.fetchone()
                
                if not result:
                    return JsonResponse({'error': 'Product not found'}, status=404)
                
                if result[0] != merchant_id:
                    return JsonResponse({'error': 'Unauthorized to edit this product'}, status=403)
                
                existing_images = json.loads(result[1])

            # Handle multipart form data
            product_name = request.POST.get('product_name')
            description = request.POST.get('description')
            original_price = request.POST.get('original_price')
            discount = request.POST.get('discount', 0.00)
            stock = request.POST.get('stock', 0)
            category_id = request.POST.get('category_id')
            
            # Get new images if any
            new_image_files = request.FILES.getlist('images')
            uploaded_urls = []

            # Validate required fields
            if not all([product_name, original_price, category_id]):
                return JsonResponse({'error': 'Product name, price, and category are required'}, status=400)

            # Handle new images
            for image_file in new_image_files:
                # Validate file type
                allowed_types = ['image/jpeg', 'image/png', 'image/jpg']
                if image_file.content_type not in allowed_types:
                    continue  # Skip invalid files

                # Validate file size (max 5MB)
                if image_file.size > 5 * 1024 * 1024:
                    continue  # Skip large files

                # Upload to S3
                image_url = upload_file_to_s3(image_file)
                uploaded_urls.append(image_url)

            # Get images to keep (if any)
            images_to_keep = request.POST.getlist('keep_images', [])
            if isinstance(images_to_keep, str):
                images_to_keep = json.loads(images_to_keep)

            # Combine kept and new images
            final_images = [img for img in existing_images if img in images_to_keep]
            final_images.extend(uploaded_urls)

            if not final_images:
                return JsonResponse({'error': 'At least one image is required'}, status=400)

            # Calculate final price
            final_price=request.POST.get('final_price')

            with connection.cursor() as cursor:
                # Check if category exists
                cursor.execute("SELECT category_id FROM categories WHERE category_id = %s", [category_id])
                if not cursor.fetchone():
                    return JsonResponse({'error': 'Invalid category'}, status=400)

                # Update product
                cursor.execute("""
                    UPDATE products 
                    SET product_name = %s,
                        description = %s,
                        original_price = %s,
                        discount = %s,
                        final_price = %s,
                        images = %s,
                        stock = %s,
                        category_id = %s
                    WHERE product_id = %s AND merchant_id = %s
                """, [
                    product_name, description, original_price,
                    discount, final_price, json.dumps(final_images),
                    stock, category_id, product_id, merchant_id
                ])

                # Get the updated product details
                cursor.execute("""
                    SELECT p.*, c.category_name 
                    FROM products p 
                    JOIN categories c ON p.category_id = c.category_id 
                    WHERE p.product_id = %s
                """, [product_id])
                
                columns = [col[0] for col in cursor.description]
                product = dict(zip(columns, cursor.fetchone()))

                # Convert JSON string to list for images
                product['images'] = json.loads(product['images'])

            return JsonResponse({
                'message': 'Product updated successfully',
                'product': product
            })

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def delete_product(request, product_id):
    if request.method == 'DELETE':
        try:
            # Check if merchant is logged in
            if 'merchant_id' not in request.session:
                return JsonResponse({'error': 'Authentication required'}, status=401)

            merchant_id = request.session['merchant_id']
            
            with connection.cursor() as cursor:
                # First verify if the product belongs to this merchant
                cursor.execute("""
                    SELECT merchant_id, images 
                    FROM products 
                    WHERE product_id = %s
                """, [product_id])
                result = cursor.fetchone()
                
                if not result:
                    return JsonResponse({'error': 'Product not found'}, status=404)
                
                if result[0] != merchant_id:
                    return JsonResponse({'error': 'Unauthorized to delete this product'}, status=403)

                # Delete the product
                cursor.execute("""
                    DELETE FROM products 
                    WHERE product_id = %s AND merchant_id = %s
                """, [product_id, merchant_id])

                if cursor.rowcount == 0:
                    return JsonResponse({'error': 'Failed to delete product'}, status=500)

            return JsonResponse({
                'message': 'Product deleted successfully',
                'product_id': product_id
            })

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def get_merchant_orders(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET method allowed'}, status=405)
    
    try:
        merchant_id = request.session.get('merchant_id')
        if not merchant_id:
            return JsonResponse({'error': 'Merchant not authenticated'}, status=401)

        with connection.cursor() as cursor:
            # Get orders for this merchant
            cursor.execute("""
                SELECT DISTINCT o.order_id, o.total_amount, o.payment_mode, o.payment_status,
                       o.created_at, a.full_name, a.phone_number, a.address_line1,
                       a.address_line2, a.city, a.state, a.postal_code, a.country
                FROM orders o
                JOIN order_items oi ON o.order_id = oi.order_id
                LEFT JOIN user_addresses a ON o.address_id = a.id
                WHERE oi.merchant_id = %s
                ORDER BY o.created_at DESC
            """, [merchant_id])
            
            columns = [col[0] for col in cursor.description]
            orders = []
            
            for row in cursor.fetchall():
                order = dict(zip(columns, row))
                
                # Get order items for this merchant only
                cursor.execute("""
                    SELECT oi.id, oi.product_id, oi.quantity, oi.price, oi.final_price,
                           oi.status, p.product_name, p.images
                    FROM order_items oi
                    JOIN products p ON oi.product_id = p.product_id
                    WHERE oi.order_id = %s AND oi.merchant_id = %s
                """, [order['order_id'], merchant_id])
                
                item_columns = [col[0] for col in cursor.description]
                order['items'] = [dict(zip(item_columns, item)) for item in cursor.fetchall()]
                
                # Calculate merchant's total for this order
                merchant_total = sum(item['final_price'] * item['quantity'] for item in order['items'])
                order['merchant_total'] = merchant_total
                
                orders.append(order)

        return JsonResponse({'orders': orders})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def update_order_item_status(request, item_id):
    if request.method != 'PUT':
        return JsonResponse({'error': 'Only PUT method allowed'}, status=405)
    
    try:
        data = json.loads(request.body.decode('utf-8'))
        status = data.get('status')
        
        if not status:
            return JsonResponse({'error': 'Status is required'}, status=400)
            
        valid_statuses = ['returned', 'placed', 'shipped', 'delivered', 'cancelled']
        if status not in valid_statuses:
            return JsonResponse({'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'}, status=400)

        merchant_id = request.session.get('merchant_id')
        if not merchant_id:
            return JsonResponse({'error': 'Merchant not authenticated'}, status=401)

        with connection.cursor() as cursor:
            # Verify order item belongs to this merchant
            cursor.execute("""
                SELECT oi.id FROM order_items oi
                WHERE oi.id = %s AND oi.merchant_id = %s
            """, [item_id, merchant_id])
            
            if not cursor.fetchone():
                return JsonResponse({'error': 'Order item not found'}, status=404)

            # Update status
            cursor.execute("""
                UPDATE order_items 
                SET status = %s 
                WHERE id = %s
            """, [status, item_id])

        return JsonResponse({'message': 'Order item status updated successfully'})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def get_merchant_order_stats(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET method allowed'}, status=405)
    
    try:
        merchant_id = request.session.get('merchant_id')
        if not merchant_id:
            return JsonResponse({'error': 'Merchant not authenticated'}, status=401)

        with connection.cursor() as cursor:
            # Get total orders and revenue
            cursor.execute("""
                SELECT 
                    COUNT(DISTINCT o.order_id) as total_orders,
                    SUM(oi.quantity * oi.final_price) as total_revenue,
                    COUNT(DISTINCT CASE WHEN oi.status = 'placed' THEN o.order_id END) as pending_orders,
                    COUNT(DISTINCT CASE WHEN oi.status = 'returned' THEN o.order_id END) as retuned_orders,
                    COUNT(DISTINCT CASE WHEN oi.status = 'shipped' THEN o.order_id END) as shipped_orders,
                    COUNT(DISTINCT CASE WHEN oi.status = 'delivered' THEN o.order_id END) as delivered_orders,
                    COUNT(DISTINCT CASE WHEN oi.status = 'rejected' THEN o.order_id END) as cancelled_orders
                FROM orders o
                JOIN order_items oi ON o.order_id = oi.order_id
                WHERE oi.merchant_id = %s
            """, [merchant_id])
            
            stats = dict(zip([col[0] for col in cursor.description], cursor.fetchone()))

            # Get recent orders (last 7 days)
            cursor.execute("""
                SELECT 
                    DATE(o.created_at) as date,
                    COUNT(DISTINCT o.order_id) as order_count,
                    SUM(oi.quantity * oi.final_price) as daily_revenue
                FROM orders o
                JOIN order_items oi ON o.order_id = oi.order_id
                WHERE oi.merchant_id = %s
                AND o.created_at >= DATE_SUB(CURRENT_DATE, INTERVAL 7 DAY)
                GROUP BY DATE(o.created_at)
                ORDER BY date DESC
            """, [merchant_id])
            
            recent_stats = []
            for row in cursor.fetchall():
                recent_stats.append({
                    'date': row[0].strftime('%Y-%m-%d'),
                    'order_count': row[1],
                    'revenue': float(row[2]) if row[2] else 0
                })

            stats['recent_stats'] = recent_stats

        return JsonResponse({'stats': stats})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
