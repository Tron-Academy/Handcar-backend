
from django.urls import path
from . import views  # Make sure to import views from the correct app

urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('generate/otp/', views.generate_otp, name='generate_otp'),
    path('login/password/', views.login_with_password, name='login_with_password'),
    path('login/send-otp/', views.send_otp, name='send_otp'),
    path('login/otp/', views.login_with_otp, name='login_with_otp'),
    path('cart/add/<int:product_id>/', views.add_to_cart, name='add_to_cart'),
    path('wishlist/add/<int:product_id>/', views.add_to_wishlist, name='add_to_wishlist'),
    path('searchproducts/', views.product_search, name='product_search'),
    path('filter/products', views.filter_products, name='filter_products'),
    path('subscribe/', views.subscribe, name='subscribe'),
    path('viewcartitems', views.display_cart, name='display_cart'),
    path('removecart', views.remove_cart_item, name='remove_cart_item')
]




