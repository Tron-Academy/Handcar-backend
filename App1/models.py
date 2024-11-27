# serializers.py
from datetime import timedelta, date

from django.contrib.auth.models import User
from django.http import JsonResponse
from django.shortcuts import get_object_or_404

from rest_framework import serializers
from django.utils import timezone
# models.py
from django.db import models


class Category(models.Model):
    name = models.CharField(max_length=255)


    def __str__(self):
        return self.name

class Brand(models.Model):
    name = models.CharField(max_length=255)


    def __str__(self):
        return self.name

class Product(models.Model):
    name = models.CharField(max_length=2000)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    brand = models.ForeignKey(Brand, on_delete=models.CASCADE)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.URLField(max_length=2000, blank=True, null=True)  # Use URLField for Cloudinary URLs
    description = models.TextField(blank=True)
    is_bestseller = models.BooleanField(default=False)
    discount_percentage = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)

    def average_rating(self):
        reviews = self.reviews.all()
        if reviews:
            return round(sum(review.rating for review in reviews) / reviews.count(), 1)
        return 0


class Review(models.Model):
    product = models.ForeignKey(Product, related_name='reviews', on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    rating = models.PositiveSmallIntegerField(default=0)  # Rating from 1 to 5
    comment = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('product', 'user')
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


class Review(models.Model):
    product = models.ForeignKey('Product', on_delete=models.CASCADE, related_name='reviews')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    rating = models.IntegerField()
    comment = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('product', 'user')  # Ensures one review per user per product

    def __str__(self):
        return f"Review by {self.user.username} on {self.product.name} - Rating: {self.rating}"


class Address(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="addresses")
    street = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    zip_code = models.CharField(max_length=20)
    country = models.CharField(max_length=100)
    is_default = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.street}, {self.city}, {self.state}, {self.zip_code}, {self.country}"

