from random import random
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_exempt
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from twilio.rest import Client
import random
from django.core.cache import cache
from .models import Product, WishlistItem, CartItem, Review, Address, Category, Brand,Vendor, Coupon, Plan, Subscriber, Subscription,Services


# @csrf_exempt
# def signup(request):
#     if request.method == 'POST':
#         # Get user details from the POST request
#         name = request.POST.get('name')
#         email = request.POST.get('email')
#         phone = request.POST.get('phone')
#         password = request.POST.get('password')
#
#         # Check if all fields are provided
#         if not all([name, email, phone, password]):
#             return JsonResponse({'error': 'All fields are required'}, status=400)
#
#         # Validate email format
#         try:
#             validate_email(email)
#         except ValidationError:
#             return JsonResponse({'error': 'Invalid email format'}, status=400)
#
#         # Check if the email already exists
#         if User.objects.filter(email=email).exists():
#             return JsonResponse({'error': 'Email is already taken'}, status=400)
#
#         # Check if the phone number is already registered
#         if User.objects.filter(username=phone).exists():
#             return JsonResponse({'error': 'Phone number is already registered'}, status=400)
#
#         # Create the user
#         user = User.objects.create(
#             username=phone,  # Using phone as the username
#             first_name=name,
#             email=email,
#             password=make_password(password)  # Hash the password
#         )
#
#         # Respond with success
#         return JsonResponse({'message': 'Signup successful!'}, status=201)
#
#     return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def signup(request):
    if request.method == 'POST':
        # Parse JSON data from the request body
        try:
            data = json.loads(request.body)
            name = data.get('name')
            email = data.get('email')
            phone = data.get('phone')
            password = data.get('password')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)

        # Check if all fields are provided
        if not all([name, email, phone, password]):
            return JsonResponse({'error': 'All fields are required'}, status=400)

        # Validate email format
        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse({'error': 'Invalid email format'}, status=400)

        # Check if the email already exists
        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email is already taken'}, status=400)

        # Check if the phone number is already registered
        if User.objects.filter(username=phone).exists():
            return JsonResponse({'error': 'Phone number is already registered'}, status=400)

        # Create the user
        try:
            user = User.objects.create_user(
                username=phone,
                first_name=name,
                email=email,
                password=password
            )
        except Exception as e:
            return JsonResponse({'error': f'Failed to create user: {str(e)}'}, status=500)

        return JsonResponse({'message': 'Signup successful!'}, status=201)

    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def send_otp(request):
    if request.method == 'POST':
        phone_number = request.POST.get('phone')  # Get the phone number from the request

        if not phone_number:
            return JsonResponse({'error': 'Phone number is required'}, status=400)

        try:
            # Initialize Twilio client
            client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)

            # Generate the OTP
            otp = generate_otp()
            message_body = f"Your OTP code is {otp}"

            # Send the OTP via Twilio
            message = client.messages.create(
                body=message_body,
                from_=settings.TWILIO_PHONE_NUMBER,
                to=phone_number
            )

            # Return success response with the message SID
            return JsonResponse({'message': 'OTP sent successfully', 'sid': message.sid}, status=200)

        except Exception as e:
            # Handle any errors and return a failure response
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)


def generate_otp(length=6):
    """Generates a random OTP of the given length"""
    return ''.join([str(random.randint(0, 9)) for _ in range(length)])

# Store OTP in cache for 5 minutes (300 seconds)
OTP_EXPIRATION_TIME = 300  # 5 minutes

def store_otp(phone, otp):
    """Stores the OTP in cache with expiration"""
    cache.set(phone, otp, timeout=OTP_EXPIRATION_TIME)

def verify_otp(phone, entered_otp):
    """Verifies if the entered OTP matches the stored one"""
    stored_otp = cache.get(phone)  # Retrieves the stored OTP from cache
    if stored_otp and stored_otp == entered_otp:
        # OTP is correct, remove it from the cache after verification
        cache.delete(phone)
        return True
    return False

# View for logging in with a password
@csrf_exempt
def login_with_password(request):
    if request.method == 'POST':
        phone = request.POST.get('phone')
        password = request.POST.get('password')

        # Assuming you are using phone as the username field
        try:
            user = User.objects.get(username=phone)
            user = authenticate(request, username=phone, password=password)
            if user is not None:
                login(request, user)
                return JsonResponse({'message': 'Login successful!'}, status=200)
            else:
                return JsonResponse({'error': 'Invalid password'}, status=400)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User does not exist'}, status=404)
    return JsonResponse({'error': 'Invalid request method'}, status=405)



# View for logging in with OTP  NOT WORKING- SHOWING INVALID OTP ERROR
@csrf_exempt
def login_with_otp(request):
    if request.method == 'POST':
        phone = request.POST.get('phone')
        entered_otp = request.POST.get('otp')

        # Verify OTP
        if verify_otp(phone, entered_otp):
            # Log in the user by phone number, assuming phone is the username
            try:
                user = User.objects.get(username=phone)
                login(request, user)
                return JsonResponse({'message': 'Login successful!'}, status=200)
            except User.DoesNotExist:
                return JsonResponse({'error': 'User does not exist'}, status=404)
        else:
            return JsonResponse({'error': 'Invalid OTP'}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

def view_products(request):
    if request.method == 'GET':
        search_query = request.GET.get('search', '')
        if search_query:
            products = Product.objects.filter(name__icontains=search_query)
        else:
            products = Product.objects.all()

        data = [
            {
                "id": product.id,
                "name": product.name,
                "category": product.category,
                "brand": product.brand,
                "price": product.price,
                "image": product.image.url if product.image else None,
                "description": product.description,
                "is_bestseller": product.is_bestseller,
            }
            for product in products
        ]
        return JsonResponse({"product": data}, safe=False)


@csrf_exempt
@login_required
def add_to_cart(request, product_id):
    if request.method == 'POST':
        product = get_object_or_404(Product, id=product_id)
        cart_item, created = CartItem.objects.get_or_create(user=request.user, product=product)

        if not created:
            # If the item is already in the cart, increase the quantity
            cart_item.quantity += 1
            cart_item.save()

        return JsonResponse({'message': 'Product added to cart', 'cart_quantity': cart_item.quantity})

    return JsonResponse({'error': 'Invalid request'}, status=400)



@csrf_exempt
def add_to_wishlist(request, product_id):
    if request.method == 'POST':
        product = get_object_or_404(Product, id=product_id)
        wishlist_item, created = WishlistItem.objects.get_or_create(user=request.user, product=product)

        # Return a JSON response with a success message or redirect
        if created:
            return JsonResponse({'message': 'Product added to wishlist', 'product_id': product_id})
        else:
            return JsonResponse({'message': 'Product already in wishlist', 'product_id': product_id})

    # If not a POST request, return a 405 Method Not Allowed
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def product_search(request):
    query = request.GET.get('search')
    accessories = Product.objects.all()

    if query:
        accessories = accessories.filter(name__icontains=query)  # Filter by name, case-insensitive

    # Prepare data for JSON response
    accessories_data = [
        {
            'id': accessory.id,
            'name': accessory.name,
            'price': accessory.price,
            'brand': accessory.brand.name,  # Get the brand name instead of the brand object
            'image_url': accessory.image.url if accessory.image and hasattr(accessory.image, 'url') else None,
            'description': accessory.description,
        }
        for accessory in accessories
    ]

    return JsonResponse({'accessories': accessories_data, 'query': query})


def filter_by_category(queryset, category_id):
    return queryset.filter(category_id=category_id)


def filter_by_aed(queryset, min_price=None, max_price=None):
    if min_price is not None:
        queryset = queryset.filter(price__gte=min_price)
    if max_price is not None:
        queryset = queryset.filter(price__lte=max_price)
    return queryset


def filter_by_brand(queryset, brand_id):
    return queryset.filter(brand_id=brand_id)


from django.utils import timezone
from datetime import timedelta

def filter_by_new_arrivals(queryset, days=30):
    recent_date = timezone.now() - timedelta(days=days)
    return queryset.filter(created_at__gte=recent_date)


def filter_by_rating(queryset, min_rating):
    return queryset.filter(rating__gte=min_rating)

@csrf_exempt
def filter_products(request):
    products = Product.objects.all()

    # Get filter parameters from request
    category_id = request.GET.get('category_id')
    min_price = request.GET.get('min_price')
    max_price = request.GET.get('max_price')
    brand_id = request.GET.get('brand_id')
    min_rating = request.GET.get('min_rating')
    new_arrivals = request.GET.get('new_arrivals')  # Expects something like 'true'

    # Apply filters
    if category_id:
        products = filter_by_category(products, category_id)

    if min_price or max_price:
        products = filter_by_aed(products, min_price=min_price, max_price=max_price)

    if brand_id:
        products = filter_by_brand(products, brand_id)

    if min_rating:
        products = filter_by_rating(products, min_rating)

    if new_arrivals == 'true':  # Check if new arrivals filter is requested
        products = filter_by_new_arrivals(products)

    # Prepare data for JSON response
    products_data = [
        {
            'id': product.id,
            'name': product.name,
            'price': product.price,
            'brand': product.brand.name,
            'image_url': product.image.url if product.image else None,
            'description': product.description,
            'rating': product.rating,
        }
        for product in products
    ]

    return JsonResponse({'products': products_data})





import logging
from django.http import JsonResponse, HttpResponseBadRequest
from urllib.parse import quote
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

@csrf_exempt
def subscribe(request):
    logger.info("subscribe view called")  # Log when the view is hit

    if request.method == 'POST':
        plan = request.POST.get('plan')
        category = request.POST.get('category')
        duration = request.POST.get('duration')

        if plan and category and duration:
            message = f"I would like to subscribe to the {plan} plan for {category} for {duration}."
            encoded_message = quote(message)
            whatsapp_url = f"https://wa.me/917025791186?text={encoded_message}"

            logger.info(f"Generated WhatsApp URL: {whatsapp_url}")  # Log the generated URL

            return JsonResponse({'whatsapp_url': whatsapp_url})
        else:
            logger.warning("Invalid subscription data")
            return HttpResponseBadRequest("Invalid subscription data.")

    logger.warning("Invalid request method")
    return HttpResponseBadRequest("Invalid request method.")

@csrf_exempt
def display_cart(request):
    if request.user.is_authenticated:
        # Get all cart items for the logged-in user
        cart_items = CartItem.objects.filter(user=request.user)

        # Prepare cart items data for JSON response
        cart_data = []
        for item in cart_items:
            cart_data.append({
                'product_name': item.product.name,
                'product_price': item.product.price,
                'quantity': item.quantity,
                'total_price': item.product.price * item.quantity,
            })

        # Calculate total price for the cart
        total_price = sum(item['total_price'] for item in cart_data)

        # Return JSON response with cart items and total price
        return JsonResponse({
            'cart_items': cart_data,
            'total_price': total_price
        })

    return JsonResponse({'error': 'User not authenticated'}, status=401)


def remove_cart_item(request, item_id):
    if request.user.is_authenticated:
        # Get the cart item based on the ID and user
        cart_item = get_object_or_404(CartItem, id=item_id, user=request.user)

        # Delete the cart item
        cart_item.delete()

        # Get all remaining cart items for the logged-in user
        cart_items = CartItem.objects.filter(user=request.user)

        # Prepare cart items data for JSON response
        cart_data = []
        for item in cart_items:
            cart_data.append({
                'product_name': item.product.name,
                'product_price': item.product.price,
                'quantity': item.quantity,
                'total_price': item.product.price * item.quantity,
            })

        # Calculate total price for the cart after removal
        total_price = sum(item['total_price'] for item in cart_data)

        # Return updated cart data
        return JsonResponse({
            'message': 'Item removed successfully',
            'cart_items': cart_data,
            'total_price': total_price
        })

    return JsonResponse({'error': 'User not authenticated'}, status=401)


@csrf_exempt
@login_required
def add_review(request, product_id):
    product = get_object_or_404(Product, id=product_id)

    # Parse JSON data from the request body
    try:
        data = json.loads(request.body)
        rating = data.get('rating')
        comment = data.get('comment')

        # Validate that required fields are provided
        if rating is None or not isinstance(rating, int) or not (1 <= rating <= 5):
            return JsonResponse({'error': 'Rating must be an integer between 1 and 5.'}, status=400)

        # Optional comment validation if needed
        if comment and not isinstance(comment, str):
            return JsonResponse({'error': 'Comment must be a string.'}, status=400)

        # Attempt to create a new review
        try:
            review = Review.objects.create(
                product=product,
                user=request.user,
                rating=rating,
                comment=comment
            )
            return JsonResponse({'message': 'Review added successfully.', 'review_id': review.id}, status=201)

        except IntegrityError:
            return JsonResponse({'error': 'You have already reviewed this product. Please edit your existing review.'},
                                status=400)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data.'}, status=400)


@csrf_exempt
def add_category(request):
    if request.method == 'POST':
        try:
            # Check if the request body exists
            if not request.body:
                return JsonResponse({"error": "Request body is empty"}, status=400)

            # Attempt to parse JSON
            data = json.loads(request.body)

            # Extract fields
            name = data.get('name')


            # Validate required fields
            if not name:
                return JsonResponse({"error": "Name is required"}, status=400)

            # Create the category
            category = Category.objects.create(name=name)
            return JsonResponse({"id": category.id, "name": category.name},
                                status=201)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid HTTP method"}, status=405)


def view_categories(request):
    if request.method == 'GET':
        search_query = request.GET.get('search', '')
        if search_query:
            categories = Category.objects.filter(name__icontains=search_query)
        else:
            categories = Category.objects.all()
        data = [{"id": cat.id, "name": cat.name} for cat in categories]
        return JsonResponse({"categories": data}, safe=False)

@csrf_exempt
def edit_category(request, category_id):
    # Retrieve the category instance by ID
    category = get_object_or_404(Category, id=category_id)

    if request.method == 'GET':
        # Return the current category details as JSON
        return JsonResponse({
            "id": category.id,
            "name": category.name,
        })


    elif request.method == 'POST':
        # Get the updated name from the request body
        try:
            data = request.POST
            new_name = data.get('name')

            if not new_name:
                return JsonResponse({"error": "Name is required"}, status=400)

            # Update and save the category
            category.name = new_name
            category.save()

            return JsonResponse({
                "message": "Category updated successfully",
                "id": category.id,
                "name": category.name,
            })
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    else:
        return JsonResponse({"error": "Invalid HTTP method"}, status=405)


@csrf_exempt
def delete_category(request, category_id):
    if request.method == 'DELETE':
        try:
            # Retrieve the category instance by ID
            category = get_object_or_404(Category, id=category_id)

            # Delete the category
            category.delete()

            return JsonResponse({"message": "Category deleted successfully"}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid HTTP method"}, status=405)

@csrf_exempt
def add_brand(request):
    if request.method == 'POST':
        try:
            # Check if the request body exists
            if not request.body:
                return JsonResponse({"error": "Request body is empty"}, status=400)

            # Attempt to parse JSON
            data = json.loads(request.body)

            # Extract fields
            name = data.get('name')


            # Validate required fields
            if not name:
                return JsonResponse({"error": "Name is required"}, status=400)

            # Create the Brand
            brands = Brand.objects.create(name=name)
            return JsonResponse({"id": brands.id, "name": brands.name},status=201)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid HTTP method"}, status=405)


def view_brand(request):
    if request.method == 'GET':
        search_query = request.GET.get('search', '')
        if search_query:
            brands = Brand.objects.filter(name__icontains=search_query)
        else:
            brands = Brand.objects.all()
        data = [{"id": brand.id, "name": brand.name} for brand in brands]
        return JsonResponse({"brands": data}, safe=False)


@csrf_exempt
def edit_brand(request, brand_id):
    # Retrieve the category instance by ID
    brand = get_object_or_404(Brand, id=brand_id)

    if request.method == 'GET':
        # Return the current category details as JSON
        return JsonResponse({
            "id": brand.id,
            "name": brand.name,
        })

    elif request.method == 'POST':
        # Get the updated name from the request body
        try:
            data = request.POST
            new_name = data.get('name')

            if not new_name:
                return JsonResponse({"error": "Name is required"}, status=400)

            # Update and save the brand
            brand.name = new_name
            brand.save()

            return JsonResponse({
                "message": "Brand updated successfully",
                "id": brand.id,
                "name": brand.name,
            })
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    else:
        return JsonResponse({"error": "Invalid HTTP method"}, status=405)


@csrf_exempt
def delete_brand(request, brand_id):
    if request.method == 'DELETE':
        try:
            # Retrieve the category instance by ID
            brand = get_object_or_404(Brand, id=brand_id)

            # Delete the category
            brand.delete()

            return JsonResponse({"message": "Brand deleted successfully"}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid HTTP method"}, status=405)



from cloudinary.uploader import upload
# @csrf_exempt
# def add_product(request):
#     if request.method == 'POST':
#         try:
#             # Check if the request contains files and form-data
#             if request.FILES.get('image'):  # Check for image file
#                 image_file = request.FILES['image']
#             else:
#                 image_file = None  # In case no image is uploaded
#
#             # Get other data from the form (using request.POST)
#             name = request.POST.get('name')
#             category_id = request.POST.get('category_id')
#             brand_id = request.POST.get('brand_id')
#             price = request.POST.get('price')
#             description = request.POST.get('description', '')
#             is_bestseller = request.POST.get('is_bestseller', False)
#             discount_percentage = request.POST.get('discount_percentage', 0)
#
#             # Validate required fields
#             if not name or not category_id or not brand_id or not price:
#                 return JsonResponse({"error": "Name, category_id, brand_id, and price are required."}, status=400)
#
#             # Retrieve related objects
#             category = get_object_or_404(Category, id=category_id)
#             brand = get_object_or_404(Brand, id=brand_id)
#
#             # Handle image upload to Cloudinary
#             image_url = None
#             if image_file:
#                 try:
#                     upload_result = upload(image_file, folder="product_images/")
#                     image_url = upload_result['secure_url']
#                 except Exception as e:
#                     return JsonResponse({"error": f"Image upload failed: {str(e)}"}, status=500)
#
#             # Create the Product instance
#             product = Product.objects.create(
#                 name=name,
#                 category=category,
#                 brand=brand,
#                 price=price,
#                 description=description,
#                 is_bestseller=is_bestseller,
#                 discount_percentage=discount_percentage,
#                 image=image_url  # Save the Cloudinary image URL
#             )
#
#             return JsonResponse({
#                 "message": "Product added successfully.",
#                 "product": {
#                     "id": product.id,
#                     "name": product.name,
#                     "category": product.category.name,
#                     "brand": product.brand.name,
#                     "price": str(product.price),
#                     "description": product.description,
#                     "is_bestseller": product.is_bestseller,
#                     "discount_percentage": product.discount_percentage,
#                     "image": product.image,  # Return Cloudinary image URL
#                     "created_at": product.created_at.strftime('%Y-%m-%d %H:%M:%S'),
#                 }
#             }, status=201)
#
#         except Exception as e:
#             return JsonResponse({"error": str(e)}, status=500)
#
#     return JsonResponse({"error": "Invalid HTTP method."}, status=405)
#

# from django.shortcuts import get_object_or_404
# from django.http import JsonResponse
# from cloudinary.uploader import upload
# from .models import Product, Category, Brand
# from django.views.decorators.csrf import csrf_exempt
# import json
#
# @csrf_exempt
# def add_product(request):
#     if request.method == 'POST':
#         try:
#             # Check if the request contains files and form-data
#             if request.FILES.get('image'):  # Check for image file
#                 image_file = request.FILES['image']
#             else:
#                 image_file = None  # In case no image is uploaded
#
#             # Get other data from the form (using request.POST)
#             name = request.POST.get('name')
#             category_name = request.POST.get('category_name')  # Use name instead of ID
#             brand_name = request.POST.get('brand_name')        # Use name instead of ID
#             price = request.POST.get('price')
#             description = request.POST.get('description', '')
#             is_bestseller = request.POST.get('is_bestseller', False)
#             discount_percentage = request.POST.get('discount_percentage', 0)
#
#             # Validate required fields
#             if not name or not category_name or not brand_name or not price:
#                 return JsonResponse({"error": "Name, category_name, brand_name, and price are required."}, status=400)
#
#             # Retrieve related objects by name
#             category = get_object_or_404(Category, name=category_name)
#             brand = get_object_or_404(Brand, name=brand_name)
#
#             # Handle image upload to Cloudinary
#             image_url = None
#             if image_file:
#                 try:
#                     upload_result = upload(image_file, folder="product_images/")
#                     image_url = upload_result['secure_url']
#                 except Exception as e:
#                     return JsonResponse({"error": f"Image upload failed: {str(e)}"}, status=500)
#
#             # Create the Product instance
#             product = Product.objects.create(
#                 name=name,
#                 category=category,
#                 brand=brand,
#                 price=price,
#                 description=description,
#                 is_bestseller=is_bestseller,
#                 discount_percentage=discount_percentage,
#                 image=image_url  # Save the Cloudinary image URL
#             )
#
#             return JsonResponse({
#                 "message": "Product added successfully.",
#                 "product": {
#                     "id": product.id,
#                     "name": product.name,
#                     "category": product.category.name,
#                     "brand": product.brand.name,
#                     "price": str(product.price),
#                     "description": product.description,
#                     "is_bestseller": product.is_bestseller,
#                     "discount_percentage": product.discount_percentage,
#                     "image": product.image,  # Return Cloudinary image URL
#                     "created_at": product.created_at.strftime('%Y-%m-%d %H:%M:%S'),
#                 }
#             }, status=201)
#
#         except Exception as e:
#             return JsonResponse({"error": str(e)}, status=500)
#
#     return JsonResponse({"error": "Invalid HTTP method."}, status=405)

@csrf_exempt
def view_products(request):
    if request.method == 'GET':
        search_query = request.GET.get('search', '')
        if search_query:
            products = Product.objects.filter(name__icontains=search_query)
        else:
            products = Product.objects.all()
        data = [{"id": product.id,
                 "name": product.name,
                 "category": product.category.name,
                 "brand": product.brand.name,
                 "price": product.price,
                 "image": product.image,
                 "description": product.description,
                 "discount_percentage": product.discount_percentage} for product in products]
        return JsonResponse({"product": data}, safe=False)
    
    

@csrf_exempt
def edit_product(request, product_id):
    if request.method == 'PUT':
        try:
            # Retrieve the product to be edited
            product = get_object_or_404(Product, id=product_id)

            # Parse JSON data
            data = json.loads(request.body)

            # Update fields if provided
            product.name = data.get('name', product.name)
            category_id = data.get('category_id')
            if category_id:
                product.category = get_object_or_404(Category, id=category_id)
            brand_id = data.get('brand_id')
            if brand_id:
                product.brand = get_object_or_404(Brand, id=brand_id)
                product.price = data.get('price', product.price)
                product.description = data.get('description', product.description)
                product.is_bestseller = data.get('is_bestseller', product.is_bestseller)
                product.discount_percentage = data.get('discount_percentage', product.discount_percentage)

            # Save the updated product
            product.save()

            return JsonResponse({"message": "Product updated successfully."}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid HTTP method."}, status=405)



@csrf_exempt
def delete_product(request, product_id):
    if request.method == 'DELETE':
        try:
            # Retrieve the category instance by ID
            products = get_object_or_404(Product, id=product_id)

            # Delete the category
            products.delete()

            return JsonResponse({"message": "Product deleted successfully"}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid HTTP method"}, status=405)



@csrf_exempt
def add_vendor(request):
    if request.method == 'POST':
        try:
            # Parse JSON data from the request body
            data = json.loads(request.body)

            vendor_name = data.get('vendor_name')
            phone_number = data.get('phone_number')
            email = data.get('email')
            password = data.get('password')

            # Validate required fields
            if not vendor_name or not phone_number or not email or not password:
                return JsonResponse({"error": "All fields are required."}, status=400)

            # Validate email format
            try:
                validate_email(email)
            except ValidationError:
                return JsonResponse({"error": "Invalid email format."}, status=400)

            # Check if email already exists
            if Vendor.objects.filter(email=email).exists():
                return JsonResponse({"error": "Email already exists."}, status=400)

            # Create the vendor
            vendor = Vendor.objects.create(
                vendor_name=vendor_name,
                phone_number=phone_number,
                email=email,
                password=password
            )

            return JsonResponse({
                "message": "Vendor added successfully.",
                "vendor": {
                    "id": vendor.id,
                    "vendor_name": vendor.vendor_name,
                    "phone_number": vendor.phone_number,
                    "email": vendor.email,
                }
            }, status=201)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data."}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid HTTP method."}, status=405)


# @csrf_exempt
# def view_vendors(request):
#     if request.method == 'GET':
#         search_query = request.GET.get('search', '')
#         if search_query:
#             vendors = Vendor.objects.filter(name__icontains=search_query)
#         else:
#             vendors = Vendor.objects.all()
#         data = [{"id": vendor.id,
#                  "name": vendor.vendor_name,
#                  "price": vendor.phone_number,
#                  "email": vendor.email} for vendor in vendors]
#         return JsonResponse({"vendor": data}, safe=False)



@csrf_exempt
def view_vendors(request):
    if request.method == 'GET':
        search_query = request.GET.get('search', '').strip()
        print("Search Query:", search_query)  # Debugging
        if search_query:
            vendors = Vendor.objects.filter(vendor_name__icontains=search_query)
        else:
            vendors = Vendor.objects.all()
        data = [{"id": vendor.id,
                 "name": vendor.vendor_name,
                 "price": vendor.phone_number,
                 "email": vendor.email} for vendor in vendors]
        return JsonResponse({"vendor": data}, safe=False)


@csrf_exempt
def edit_vendor(request, vendor_id):
    if request.method == 'GET':
        try:
            # Retrieve the vendor
            vendor = get_object_or_404(Vendor, id=vendor_id)

            # Return vendor data as JSON
            vendor_data = {
                "vendor_name": vendor.vendor_name,
                "email": vendor.email,
                "phone_number": vendor.phone_number,
                "whatsapp_number": vendor.whatsapp_number,
                "location": vendor.location
            }
            return JsonResponse(vendor_data, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    elif request.method == 'PUT':
        try:
            # Retrieve the vendor to be edited
            vendor = get_object_or_404(Vendor, id=vendor_id)

            # Parse JSON data
            data = json.loads(request.body)

            # Update fields if provided
            vendor.vendor_name = data.get('vendor_name', vendor.vendor_name)  # Vendor can edit name
            vendor.email = data.get('email', vendor.email)  # Vendor can edit email
            vendor.password = data.get('password', vendor.password)  # Vendor can change password
            vendor.phone_number = data.get('phone_number', vendor.phone_number)  # Vendor can edit phone number

            # Vendor-specific fields that only vendors can update
            vendor.whatsapp_number = data.get('whatsapp_number', vendor.whatsapp_number)
            vendor.location = data.get('location', vendor.location)

            # Save the updated vendor
            vendor.save()

            return JsonResponse({"message": "Vendor updated successfully."}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid HTTP method."}, status=405)


@csrf_exempt
def delete_vendor(request, vendor_id):
    if request.method == 'DELETE':
        try:
            # Retrieve the vendor instance by ID
            vendors = get_object_or_404(Vendor, id=vendor_id)

            # Delete the vendor
            vendors.delete()

            return JsonResponse({"message": "Vendor deleted successfully"}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid HTTP method"}, status=405)


@csrf_exempt
def add_coupon(request):
    if request.method == 'POST':
        try:
            # Parse JSON data from the request body
            data = json.loads(request.body)

            name = data.get('name')
            coupon_code = data.get('coupon_code')
            discount_percentage = data.get('discount_percentage')
            start_date = data.get('start_date')
            end_date = data.get('end_date')
            description = data.get('description')

            # Validate required fields
            if not name or not coupon_code or not discount_percentage or not start_date or not end_date or not description:
                return JsonResponse({"error": "All fields are required."}, status=400)

            # Create the vendor
            coupon = Coupon.objects.create(
                name=name,
                coupon_code=coupon_code,
                discount_percentage=discount_percentage,
                start_date=start_date,
                end_date = end_date,
                description = description
            )

            return JsonResponse({
                "message": "Coupon added successfully.",
                "coupon": {
                    "id": coupon.id,
                    "name": coupon.name,
                    "coupon_code": coupon.coupon_code,
                    "discount_percentage": coupon.discount_percentage,
                    "start_date": coupon.start_date,
                    "end_date": coupon.end_date,
                    "description": coupon.description
                }
            }, status=201)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data."}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid HTTP method."}, status=405)



@csrf_exempt
def view_coupons(request):
    if request.method == 'GET':
        search_query = request.GET.get('search', '')
        if search_query:
            coupons = Coupon.objects.filter(name__icontains=search_query)
        else:
            coupons = Coupon.objects.all()
        data = [{   "id": coupon.id,
                    "name": coupon.name,
                    "coupon_code": coupon.coupon_code,
                    "discount_percentage": coupon.discount_percentage,
                    "start_date": coupon.start_date,
                    "end_date": coupon.end_date,
                    "description": coupon.description} for coupon in coupons]
        return JsonResponse({"coupon": data}, safe=False)



@csrf_exempt
def edit_coupons(request, coupon_id):
    if request.method == 'PUT':
        try:
            # Retrieve the vendor to be edited
            coupons = get_object_or_404(Coupon, id=coupon_id)

            # Parse JSON data
            data = json.loads(request.body)

            # Update fields if provided
            coupons.name = data.get('name', coupons.name)
            coupons.coupon_code = data.get('coupon_code', coupons.coupon_code)
            coupons.discount_percentage = data.get('discount_percentage', coupons.discount_percentage)
            coupons.start_date = data.get('start_date', coupons.start_date)
            coupons.end_date = data.get('end_date', coupons.end_date)
            coupons.description = data.get('description', coupons.description)

            # Log the updated values
            print("Updated Coupon Data:", coupons.name, coupons.coupon_code, coupons.discount_percentage)

            # Save the updated coupon
            coupons.save()

            return JsonResponse({"message": "Coupon updated successfully."}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid HTTP method."}, status=405)



@csrf_exempt
def delete_coupons(request, coupon_id):
    if request.method == 'DELETE':
        try:
            # Retrieve the coupon instance by ID
            coupon = get_object_or_404(Coupon, id=coupon_id)

            # Delete the coupon
            coupon.delete()

            return JsonResponse({"message": "Coupon deleted successfully"}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid HTTP method"}, status=405)


@csrf_exempt
def add_plan(request):
    if request.method == 'POST':
        try:
            # Parse JSON data from the request body
            data = json.loads(request.body)

            name = data.get('name')
            service_type = data.get('service_type')
            duration = data.get('duration')
            price = data.get('price')
            description = data.get('description')


            # Validate required fields
            if not name or not service_type or not duration or not price or not description:
                return JsonResponse({"error": "All fields are required."}, status=400)

            # Create the vendor
            plan = Plan.objects.create(
                name=name,
                service_type=service_type,
                duration=duration,
                price=price,
                description = description
            )

            return JsonResponse({
                "message": "Plan added successfully.",
                "coupon": {
                    "id": plan.id,
                    "name": plan.name,
                    "service_type": plan.service_type,
                    "duration": plan.duration,
                    "price": plan.price,
                    "description": plan.description
                }
            }, status=201)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data."}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid HTTP method."}, status=405)



@csrf_exempt
def view_plans(request):
    if request.method == 'GET':
        search_query = request.GET.get('search', '')
        if search_query:
            plans = Plan.objects.filter(name__icontains=search_query)
        else:
            plans = Plan.objects.all()
        data = [{  "id": plan.id,
                    "name": plan.name,
                    "service_type": plan.service_type,
                    "duration": plan.duration,
                    "price": plan.price,
                    "description": plan.description} for plan in plans]
        return JsonResponse({"plan": data}, safe=False)



@csrf_exempt
def edit_plan(request, plan_id):
    if request.method == 'PUT':
        try:
            # Retrieve the plan to be edited
            plans = get_object_or_404(Plan, id=plan_id)

            # Parse JSON data
            data = json.loads(request.body)

            # Update fields if provided
            plans.name = data.get('name', plans.name)
            plans.service_type = data.get('service_type', plans.service_type)
            plans.duration = data.get('duration', plans.duration)
            plans.price = data.get('price', plans.price)
            plans.description = data.get('description', plans.description)

            # Save the updated plan
            plans.save()

            return JsonResponse({"message": "Coupon updated successfully."}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid HTTP method."}, status=405)



@csrf_exempt
def delete_plan(request, plan_id):
    if request.method == 'DELETE':
        try:
            # Retrieve the coupon instance by ID
            plan = get_object_or_404(Plan, id=plan_id)

            # Delete the coupon
            plan.delete()

            return JsonResponse({"message": "Plan deleted successfully"}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid HTTP method"}, status=405)

@csrf_exempt
def search_products(request):
    query = request.GET.get('query', '')  # Get the search query from the request
    products = Product.objects.filter(name__icontains=query)  # Filter products by name
    # You can add more filters like category or brand here
    results = [
        {
            "id": product.id,
            "name": product.name,
            "category": product.category.name,
            "brand": product.brand.name,
            "price": float(product.price),
            "promoted": product.promoted,
        }
        for product in products
    ]
    return JsonResponse({"products": results})


@csrf_exempt
def promote_product(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        product_id = data.get('product_id')
        product = get_object_or_404(Product, id=product_id)
        product.promoted = True  # Mark as promoted
        product.save()
        return JsonResponse({"message": "Product promoted successfully!", "promoted": True})
    return JsonResponse({"error": "Invalid request method"}, status=400)


def view_promoted_products(request):
    if request.method == 'GET':
        # Filter products where promoted is True
        promoted_products = Product.objects.filter(promoted=True)

        promoted_products_list = [
            {
                "id": product.id,
                "name": product.name,
                "category": product.category.name,
                "brand": product.brand.name,
                "price": str(product.price),
                "description": product.description,
                "is_bestseller": product.is_bestseller,
                "discount_percentage": product.discount_percentage,
                "image": product.image,
                "created_at": product.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            }
            for product in promoted_products
        ]

        return JsonResponse({"promoted_products": promoted_products_list}, status=200)

    return JsonResponse({"error": "Invalid request method"}, status=400)


@csrf_exempt
def remove_promoted_product(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)  # Parse the JSON request body
            product_id = data.get('product_id')  # Get the product ID from the request
            product = get_object_or_404(Product, id=product_id)  # Retrieve the product

            if product.promoted:  # Check if the product is currently promoted
                product.promoted = False  # Set promoted to False
                product.save()  # Save the updated product
                return JsonResponse({"message": "Product removed from promoted successfully!", "promoted": False})
            else:
                return JsonResponse({"message": "Product is not promoted.", "promoted": False})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=400)


def search_brands(request):
    query = request.GET.get('query','')
    brand = Brand.objects.filter(name__icontains=query)
    results = [
        {
            "id": brands.id,
            "name": brands.name,
            "promoted": brands.promoted,
        }
        for brands in brand
    ]
    return JsonResponse({"brand": results})

@csrf_exempt
def promote_brand(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        brand_id = data.get('brand_id')
        brand = get_object_or_404(Brand, id=brand_id)
        brand.promoted = True  # Mark as promoted
        brand.save()
        return JsonResponse({"message": "Brand promoted successfully!", "promoted": True})
    return JsonResponse({"error": "Invalid request method"}, status=400)


def view_promoted_brands(request):
    if request.method == 'GET':
        # Filter products where promoted is True
        promoted_brands = Brand.objects.filter(promoted=True)

        promoted_brands_list = [
            {
                "id": brand.id,
                "name": brand.name

            }
            for brand in promoted_brands
        ]

        return JsonResponse({"promoted_products": promoted_brands_list}, status=200)

    return JsonResponse({"error": "Invalid request method"}, status=400)


@csrf_exempt
def remove_promoted_brand(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)  # Parse the JSON request body
            brand_id = data.get('brand_id')  # Get the brand ID from the request
            brand = get_object_or_404(Brand, id=brand_id)  # Retrieve the brand

            if brand.promoted:  # Check if the brand is currently promoted
                brand.promoted = False  # Set promoted to False
                brand.save()  # Save the updated brand
                return JsonResponse({"message": "Brand removed from promoted successfully!", "promoted": False})
            else:
                return JsonResponse({"message": "Brand is not promoted.", "promoted": False})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=400)

# DATE ISSUE WAS NOT THERE FOR START DATE
# @csrf_exempt
# def add_subscriber(request):
#     try:
#         data = json.loads(request.body)
#
#         email = data.get('email')
#         service_type = data.get('service_type')
#         plan = data.get('plan')
#         duration = data.get('duration')
#         start_date = data.get('start_date')
#         status = data.get('status')
#
#         # Validate email
#         if not User.objects.filter(email=email).exists():
#             return JsonResponse({'error': 'No such user registered.'}, status=400)
#
#         # Save subscriber
#         subscriber = Subscriber(
#             email=email,
#             service_type=service_type,
#             plan=plan,
#             duration=duration,
#             start_date=parse_date(start_date),
#             status=status
#         )
#         subscriber.save()
#
#         return JsonResponse({'message': 'Subscriber added successfully.'}, status=201)
#
#     except json.JSONDecodeError:
#         return JsonResponse({'error': 'Invalid JSON.'}, status=400)
#     except Exception as e:
#         return JsonResponse({'error': str(e)}, status=500)
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password, check_password
from .models import Vendor
import json

@csrf_exempt
def update_vendor(request, vendor_id):
    try:
        vendor = Vendor.objects.get(id=vendor_id)

        if request.method == 'POST':
            data = json.loads(request.body)

            # Update email
            email = data.get('email')
            if email:
                vendor.email = email

            # Update password
            password = data.get('password')
            if password:
                vendor.password = make_password(password)  # Hash the password before saving

            # Update location
            location = data.get('location')
            if location:
                vendor.location = location

            vendor.save()

            return JsonResponse({'message': 'Vendor details updated successfully.'}, status=200)

        return JsonResponse({'error': 'Invalid request method.'}, status=405)

    except Vendor.DoesNotExist:
        return JsonResponse({'error': 'Vendor not found.'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.dateparse import parse_date
import json
from datetime import datetime
from .models import Subscriber
from django.contrib.auth.models import User


@csrf_exempt
def add_subscriber(request):
    try:
        data = json.loads(request.body)

        email = data.get('email')
        postal_code = data.get('postal_code')
        service_type = data.get('service_type')
        plan = data.get('plan')
        duration = data.get('duration')
        assigned_vendor = data.get('assigned_vendor')
        start_date = data.get('start_date')

        # Validate email
        if not User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'No such user registered.'}, status=400)

        # Validate and parse start_date
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            except ValueError:
                return JsonResponse({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=400)
        else:
            return JsonResponse({'error': 'Start date is required.'}, status=400)

        # Validate duration
        try:
            duration = int(duration)
        except (ValueError, TypeError):
            return JsonResponse({'error': 'Duration must be an integer.'}, status=400)

        # Save subscriber
        subscriber = Subscriber(
            email=email,
            postal_code=postal_code,
            service_type=service_type,
            plan=plan,
            duration=duration,
            assigned_vendor=assigned_vendor,
            start_date=start_date,
        )
        subscriber.save()

        return JsonResponse({'message': 'Subscriber added successfully.', 'end_date': subscriber.end_date}, status=201)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON.'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def view_subscribers(request):
    if request.method == 'GET':
        search_query = request.GET.get('search', '')
        if search_query:
            subscriber = Subscriber.objects.filter(name__icontains=search_query)
        else:
            subscriber = Subscriber.objects.all()
        data = [{  "id": subscribers.id,
                    "email": subscribers.email,
                    "postal_code": subscribers.postal_code,
                    "service_type": subscribers.service_type,
                    "plan": subscribers.plan,
                    "duration": subscribers.duration,
                    "start_date": subscribers.start_date,
                    "end_date": subscribers.end_date,
                    "assigned_vendor": subscribers.assigned_vendor} for subscribers in subscriber]
        return JsonResponse({"user": data}, safe=False)





def view_users(request):
    if request.method == 'GET':
        search_query = request.GET.get('search', '')
        if search_query:
            user = User.objects.filter(username__icontains=search_query)
        else:
            user = User.objects.filter(is_superuser=False)
        data = [{  "id": users.id,
                    "username": users.username,
                    "first_name": users.first_name,
                    "last_name": users.last_name,
                    "email": users.email} for users in user]
        return JsonResponse({"user": data}, safe=False)



import cloudinary.uploader
from django.http import JsonResponse
import json
@csrf_exempt
# def add_service(request):
#     if request.method == 'POST':
#         print("POST Data:", request.POST)  # Log the POST data
#         print("FILES Data:", request.FILES)  # Log the FILES data
#         try:
#             # Get the form data
#             service_name = request.POST.get('Service_name')
#             service_category = request.POST.get('Service_category')
#             service_details = request.POST.get('Service_details')
#             rate = request.POST.get('Rate')
#             image = request.FILES.get('Image')  # The image file sent from the frontend
#             print("Service_name:", service_name)
#             print("Service_category:", service_category)
#             print("Service_details:", service_details)
#             print("Rate:", rate)
#             print("Image:", image)
#
#             # Validate required fields
#             if not all([service_name, service_category, service_details, rate, image]):
#                 return JsonResponse({"error": "All fields are required."}, status=400)
#
#             # Upload image to Cloudinary
#             try:
#                 upload_result = cloudinary.uploader.upload(image)  # Upload the image file
#                 image_url = upload_result.get('secure_url')  # Get the URL of the uploaded image
#             except Exception as e:
#                 return JsonResponse({"error": f"Image upload failed: {str(e)}"}, status=500)
#
#             # Save the service to the database
#             service = Services.objects.create(
#                 Service_name=service_name,
#                 Service_category=service_category,
#                 Service_details=service_details,
#                 Rate=rate,
#                 Image=image_url  # Save the Cloudinary image URL
#             )
#
#             return JsonResponse({
#                 "message": "Service added successfully.",
#                 "service_id": service.id,
#                 "image_url": image_url
#             }, status=201)
#
#         except json.JSONDecodeError:
#             return JsonResponse({"error": "Invalid JSON data."}, status=400)
#         except Exception as e:
#             return JsonResponse({"error": str(e)}, status=500)
#
#     return JsonResponse({"error": "Invalid HTTP method."}, status=405)
def add_service(request):
    if request.method == 'POST':
        try:
            # Get the form data
            service_name = request.POST.get('Service_name')
            service_category = request.POST.get('Service_category')
            service_details = request.POST.get('Service_details')
            rate = request.POST.get('Rate')
            image = request.FILES.get('Image')

            # Debugging logs
            print("Service_name:", service_name)
            print("Service_category:", service_category)
            print("Service_details:", service_details)
            print("Rate:", rate)
            print("Image:", image)

            # Validate required fields
            if not all([service_name, service_category, service_details, rate, image]):
                return JsonResponse({"error": "All fields are required."}, status=400)

            # Validate numeric fields
            try:
                rate = float(rate)
            except ValueError:
                return JsonResponse({"error": "Rate must be a numeric value."}, status=400)

            # Upload image to Cloudinary
            try:
                upload_result = cloudinary.uploader.upload(image)
                image_url = upload_result.get('secure_url')
            except Exception as e:
                print(f"Cloudinary upload error: {e}")
                return JsonResponse({"error": f"Image upload failed: {str(e)}"}, status=500)

            # Save the service to the database
            service = Services.objects.create(
                Service_name=service_name,
                Service_category=service_category,
                Service_details=service_details,
                Rate=rate,
                Image=image_url  # Save the Cloudinary image URL
            )

            return JsonResponse({
                "message": "Service added successfully.",
                "service_id": service.id,
                "image_url": image_url
            }, status=201)

        except Exception as e:
            print(f"Error: {e}")
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid HTTP method."}, status=405)



def view_services(request):
    if request.method == 'GET':
        services = Services.objects.all()
        service_list = [
            {
                'service_name' : data.Service_name,
                'service_category': data.Service_category,
                'service_details': data.Service_category,
                'rate': data.Rate,
                'image': data.Image
            }
            for data in services
        ]
        return JsonResponse({'Service List:': service_list})
    return JsonResponse({'Error': 'Invalid request method'})


from django.contrib.auth import authenticate

from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
# @csrf_exempt
# def admin_login(request):
#     if request.method == 'POST':
#         username = request.data.get('username')
#         password = request.data.get('password')
#
#         user = authenticate(username=username, password=password)
#
#         if user and user.is_superuser:
#             # Generate JWT tokens
#             refresh = RefreshToken.for_user(user)
#             return Response({
#                 "message": "Admin login successful",
#                 "access_token": str(refresh.access_token),
#                 "refresh_token": str(refresh)
#             })
#
#         return Response({"error": "Invalid admin credentials"}, status=status.HTTP_401_UNAUTHORIZED)

@csrf_exempt
# def admin_login(request):
#     if request.method == 'POST':
#         username = request.POST.get('username')
#         password = request.POST.get('password')
#
#         print(f"Username: {username}, Password: {password}")  # Debug input
#
#         user = authenticate(username=username, password=password)
#
#         if user:
#             print(f"User authenticated: {user.username}, Is superuser: {user.is_superuser}")  # Debug authentication
#         else:
#             print("Authentication failed")
#
#         if user and user.is_superuser:
#             refresh = RefreshToken.for_user(user)
#             response= JsonResponse({
#                 "message": "Admin login successful",
#                 "access_token": str(refresh.access_token),
#                 "refresh_token": str(refresh)
#             })
#             response.set_cookie(
#                 'access_token', str(refresh.access_token),
#                 max_age=timedelta(minutes=15), httponly=True, samesite='Lax'
#             )
#             response.set_cookie(
#                 'refresh_token', str(refresh),
#                 max_age=timedelta(days=1), httponly=True, samesite='Lax'
#             )
#             return response
#
#         return JsonResponse({"error": "Invalid admin credentials"}, status=401)
#
#     return JsonResponse({"error": "Method not allowed"}, status=405)


@csrf_exempt
def admin_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)
        if user and user.is_superuser:
            refresh = RefreshToken.for_user(user)
            response = JsonResponse({
                "message": "Admin login successful",
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh)
            })
            # Set cookies
            response.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                value=str(refresh.access_token),
                httponly=True,  # Prevent access via JavaScript
                secure=False,  # Set True in production for HTTPS
                samesite='Lax',  # Adjust as per requirement
            )
            response.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                value=str(refresh),
                httponly=True,
                secure=False,
                samesite='Lax',
            )
            return response

        return JsonResponse({"error": "Invalid admin credentials"}, status=401)

    return JsonResponse({"error": "Method not allowed"}, status=405)


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

@csrf_exempt
def UserLogin(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)

        if user and not user.is_superuser:
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            response = JsonResponse({
                "message": "User login successful",
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh)
            })
            response.set_cookie(
                'access_token', str(refresh.access_token),
                max_age=timedelta(minutes=15), httponly=True, samesite='Lax'
            )
            response.set_cookie(
                'refresh_token', str(refresh),
                max_age=timedelta(days=1), httponly=True, samesite='Lax'
            )
            return response

        return JsonResponse({"error": "Invalid user credentials"}, status=401)

    return JsonResponse({"error": "Invalid request method"}, status=405)



from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from django.http import JsonResponse
from .models import Vendor

@csrf_exempt
def VendorLogin(request):
    if request.method == 'POST':
        phone_number = request.POST.get('phone_number')
        password = request.POST.get('password')

        # Debugging: print the phone number and password to check what's being received
        print("Received phone number:", phone_number)
        print("Received password:", password)

        try:
            vendor = Vendor.objects.get(phone_number=phone_number)
            # Debugging: print the vendor object to see if it's being retrieved
            print("Vendor found:", vendor)

            # Directly compare the entered password with the stored password
            if password == vendor.password:
                # You need to create a custom token for the vendor
                refresh = RefreshToken()
                refresh['vendor_id'] = vendor.id  # Store vendor-specific info in the token

                return JsonResponse({
                    "message": "Vendor login successful",
                    "access_token": str(refresh.access_token),
                    "refresh_token": str(refresh)
                })
            else:
                return JsonResponse({"error": "Invalid password"}, status=401)
        except Vendor.DoesNotExist:
            return JsonResponse({"error": "Vendor not found"}, status=404)

    return JsonResponse({"error": "Invalid request method"}, status=405)

