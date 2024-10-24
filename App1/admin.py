from datetime import timedelta

from django.contrib import admin
from .models import Product,Category,Brand,CartItem,WishlistItem,Subscription
# Register your models here.


admin.site.register(Product)
admin.site.register(Category)
admin.site.register(Brand)
admin.site.register(CartItem)
admin.site.register(WishlistItem)
admin.site.register(Subscription)
