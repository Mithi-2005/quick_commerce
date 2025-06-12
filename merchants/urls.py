from django.urls import path
from . import views

urlpatterns = [
    path('signup/', views.merchant_signup, name='merchant_signup'),
    path('login/', views.merchant_login, name='merchant_login'),
    path('logout/', views.merchant_logout, name='merchant_logout'),
    path('send-otp/', views.send_verification_otp, name='send_verification_otp'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('upload-image/', views.upload_product_image, name='upload_product_image'),
    path('products/add/', views.add_product, name='add_product'),
    path('products/upload-images/', views.upload_product_images, name='upload_product_images'),
    path('products/<int:product_id>/edit/', views.edit_product, name='edit_product'),
    path('products/<int:product_id>/delete/', views.delete_product, name='delete_product'),
] 