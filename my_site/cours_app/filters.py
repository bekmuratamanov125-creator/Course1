from django_filters.rest_framework import FilterSet
from .models import  Course


class CourseFilter(FilterSet):
    class Meta:
        model = Course
        fields = {
            'subcategory': ['exact'],
            'level': ['exact'],
            'price': ['gt', 'lt'],
            'created_by': ['exact'],
            'language': ['exact'],
            'is_certificate': ['exact'],
        }