
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
    path('viewcartitems/', views.display_cart, name='display_cart'),
    path('removecart/', views.remove_cart_item, name='remove_cart_item'),
    path('add_review/<int:product_id>/', views.add_review, name= 'add_review'),
    path('add_category', views.add_category, name='add_category'),
    path('view_category', views.view_categories, name='view_categories'),
    path('view_product', views.view_products, name='view_products'),
    path('edit_category/<int:category_id>/', views.edit_category, name='edit_category'),
    path('delete_category/<int:category_id>/', views.delete_category, name='delete_category'),
    path('add_brand', views.add_brand, name='add_brand'),
    path('view_brand', views.view_brand, name='view_brand'),
    path('edit_brand/<int:brand_id>/',views.edit_brand, name='edit_brand'),
    path('delete_brand/<int:brand_id>/', views.delete_brand, name='delete_brand'),
    path('add_product', views.add_product, name='add_product'),


]




