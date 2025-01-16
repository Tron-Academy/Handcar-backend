
from django.urls import path
from . import views  # Make sure to import views from the correct app
from rest_framework_simplejwt.views import TokenRefreshView
from .views import AddToCartView, DisplayCartView, UpdateCartItemView
urlpatterns = [
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('signup', views.signup, name='signup'),
    path('generate/otp/', views.generate_otp, name='generate_otp'),
    # path('login/password/', views.login_with_password, name='login_with_password'),
    path('login/send-otp/', views.send_otp, name='send_otp'),
    path('login/otp/', views.login_with_otp, name='login_with_otp'),
    path('add_to_wishlist/<int:product_id>/', views.add_to_wishlist, name='add_to_wishlist'),
    path('wishlist_items', views.wishlist_items, name='wishlist_items'),
    path('searchproducts/', views.product_search, name='product_search'),
    path('filter/products', views.filter_products, name='filter_products'),
    path('subscribe/', views.subscribe, name='subscribe'),

    path('add_to_cart/<int:product_id>/', AddToCartView.as_view(), name='add_to_cart'),
    path('display_cart', DisplayCartView.as_view(), name='display_cart'),
    path('update_cart/<int:cart_item_id>/', UpdateCartItemView.as_view(), name='update_cart'),
    # path('viewcartitems/', views.display_cart, name='display_cart'),
    path('removecart/<int:item_id>/', views.RemoveCartItemView.as_view(), name='remove_cart_item'),
    path('add_review/<int:product_id>/', views.add_review, name= 'add_review'),
    path('add_category', views.add_category, name='add_category'),
    path('view_category', views.view_categories, name='view_categories'),
    # path('view_product', views.view_products, name='view_products'),
    path('edit_category/<int:category_id>/', views.edit_category, name='edit_category'),
    path('delete_category/<int:category_id>/', views.delete_category, name='delete_category'),
    path('add_brand', views.add_brand, name='add_brand'),
    path('view_brand', views.view_brand, name='view_brand'),
    path('edit_brand/<int:brand_id>/',views.edit_brand, name='edit_brand'),
    path('delete_brand/<int:brand_id>/', views.delete_brand, name='delete_brand'),
    path('add_product', views.add_product, name='add_product'),
    path('view_products', views.view_products, name='view_products'),
    path('edit_product/<int:product_id>/', views.edit_product, name='edit_product'),
    path('delete_product/<int:product_id>/', views.delete_product, name='delete_product'),
    path('add_vendor_by_admin', views.add_vendor_by_admin, name='add_vendor'),
    path('add_service_category', views.add_service_category, name='add_service_category'),
    path('view_vendors', views.view_vendors, name='view_vendors'),
    path('edit_vendor_profile/<int:vendor_id>/', views.edit_vendor_profile, name='edit_vendor_profile'),
    path('delete_vendor/<int:vendor_id>/', views.delete_vendor, name='delete_vendor'),
    path('add_coupon', views.add_coupon, name='add_coupon'),
    path('view_coupons', views.view_coupons, name='view_coupons'),
    path('edit_coupons/<int:coupon_id>/', views.edit_coupons, name='edit_coupons'),
    path('delete_coupons/<int:coupon_id>/', views.delete_coupons, name='delete_coupons'),
    path('add_plan', views.add_plan, name='add_plan'),
    path('view_plans', views.view_plans, name='view_plans'),
    path('edit_plan/<int:plan_id>/', views.edit_plan, name='edit_plan'),
    path('delete_plan/<int:plan_id>/', views.delete_plan, name='delete_plan'),
    path('search_products', views.search_products, name='search_products'),
    path('promote_product', views.promote_product, name='promote_product'),
    path('view_promoted_products', views.view_promoted_products, name='view_promoted_products'),
    path('remove_promoted_product', views.remove_promoted_product, name='remove_promoted_product'),
    path('search_brands', views.search_brands, name='search_brands'),
    path('promote_brand', views.promote_brand, name='promote_brand'),
    path('view_promoted_brands', views.view_promoted_brands, name='view_promoted_brands'),
    path('remove_promoted_brand', views.remove_promoted_brand, name='remove_promoted_brand'),
    path('add_subscriber', views.add_subscriber, name='add_subscriber'),
    path('view_subscribers', views.view_subscribers, name='view_subscribers'),
    path('view_users/', views.view_users, name='view_users'),
    path('add_service', views.add_service, name='add_service'),
    path('view_services', views.view_services, name='view_services'),
    path('edit_service/<int:service_id>/', views.edit_service, name='edit_service'),
    path('delete_service/<int:service_id>/',views.delete_service, name='delete_service'),
    path('admin_login', views.admin_login, name='admin_login'),
    path('UserLogin', views.UserLogin, name='UserLogin'),
    path('VendorLogin', views.VendorLogin, name='VendorLogin'),
    path('Logout', views.Logout, name='Logout'),
    path('add_address', views.add_address, name='add_address'),
    path('view_addresses', views.view_addresses, name='view_addresses'),
    path('set_default_address/<int:address_id>/', views.set_default_address, name='set_default_address'),
    path('shipping_address', views.shipping_address, name='shipping_address'),
    path('view_service_user', views.view_service_user, name='view_service_user'),
    path('view_service_categories_user', views.view_service_categories_user, name='view_service_categories_user'),
    path('view_single_service_user/<int:service_id>/', views.view_single_service_user, name='view_single_service_user'),
    path('log_service_interaction', views.log_service_interaction, name='log_service_interaction'),
    path('get_service_interaction_logs_admin', views.get_service_interaction_logs_admin, name='get_service_interaction_logs'),
    path('add_service_rating', views.add_service_rating, name='add_service_rating'),
    path('add_service_rating', views.add_service_rating, name='add_service_rating'),
    path('view_service_rating', views.view_service_rating, name='view_service_rating'),
    # path('get_nearby_services', views.get_nearby_services, name='get_nearby_services'),
    path('view_service_by_users', views.view_service_by_users, name='view_service_by_users')
]




