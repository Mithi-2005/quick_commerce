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
]