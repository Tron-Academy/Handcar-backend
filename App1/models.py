# serializers.py
from datetime import timedelta, date

from django.contrib.auth.models import User

from rest_framework import serializers
from django.utils import timezone
# models.py
from django.db import models


class Category(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name

class Brand(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name

class Product(models.Model):
    name = models.CharField(max_length=255)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    brand = models.ForeignKey(Brand, on_delete=models.CASCADE)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.ImageField(upload_to='product_images/', blank=True, null=True)  # For product images
    description = models.TextField(blank=True)
    rating = models.DecimalField(max_digits=2, decimal_places=1, default=0)
    is_bestseller = models.BooleanField(default=False)
    discount_percentage = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.name

    @property
    def discounted_price(self):
        if self.discount_percentage > 0:
            return self.price * (1 - (self.discount_percentage / 100))
        return self.price

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name']

class BrandSerializer(serializers.ModelSerializer):
    class Meta:
        model = Brand
        fields = ['id', 'name']

class ProductSerializer(serializers.ModelSerializer):
    category = CategorySerializer()
    brand = BrandSerializer()

    class Meta:
        model = Product
        fields = ['id', 'name', 'price', 'discounted_price', 'rating', 'is_bestseller', 'image', 'category', 'brand']

# Cart Model
class CartItem(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)

    def __str__(self):
        return f"{self.user.username} - {self.product.name} (x{self.quantity})"

# Wishlist Model
class WishlistItem(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.user.username} - {self.product.name}"


# Choices for plan and category
PLAN_CHOICES = [
    ('basic', 'Basic'),
    ('premium', 'Premium'),
    ('luxury', 'Luxury')
]

CATEGORY_CHOICES = [
    ('car_wash', 'Car Wash'),
    ('maintenance', 'Maintenance')
]

DURATION_CHOICES = [
    (6, '6 months'),
    (12, '12 months'),
]

class Subscription(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    plan = models.CharField(max_length=10, choices=PLAN_CHOICES)
    category = models.CharField(max_length=15, choices=CATEGORY_CHOICES)
    duration_months = models.IntegerField(choices=DURATION_CHOICES)  # Restrict duration to 6 or 12 months
    start_date = models.DateField(auto_now_add=True)  # Automatically set when subscription is created
    end_date = models.DateField()
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.username} - {self.plan} plan for {self.category}"



