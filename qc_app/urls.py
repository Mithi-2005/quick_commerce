from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_api, name='login_api'),
    path('signup/', views.signup_api, name='signup_api'),
    path('send_otp/', views.send_otp_api, name='send_otp_api'),
    path('verify_otp/', views.verify_otp_api, name='verify_otp_api'),
    path('products/search/', views.search_products, name='search_products'),
    path('products/<int:product_id>/', views.get_product_by_id, name='get_product_by_id'),
    path('products/category/<int:category_id>/', views.get_products_by_category, name='get_products_by_category'),
    path('products/merchant/<int:merchant_id>/', views.get_products_by_merchant, name='get_products_by_merchant'),
    path('addresses/add/', views.add_address, name='add_address'),
    path('addresses/<int:address_id>/edit/', views.edit_address, name='edit_address'),
    path('addresses/<int:address_id>/delete/', views.delete_address, name='delete_address'),
    path('addresses/user/<int:user_id>/', views.get_user_addresses, name='get_user_addresses'),
    path('addresses/<int:address_id>/', views.get_address_by_id, name='get_address_by_id'),
    
    # Cart endpoints
    path('cart/add/', views.add_to_cart, name='add_to_cart'),
    path('cart/', views.get_cart, name='get_cart'),
    path('cart/items/<int:item_id>/update/', views.update_cart_item, name='update_cart_item'),
    path('cart/items/<int:item_id>/remove/', views.remove_from_cart, name='remove_from_cart'),
    
    # Order endpoints
    path('orders/place/', views.place_order, name='place_order'),
    path('orders/', views.get_orders, name='get_orders'),
]