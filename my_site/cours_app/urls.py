from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (UserProfileViewSet, TeacherViewSet, NetworkTeachersViewSet,CategoryListAPIView, CategoryDetailAPIView, SubCategoryListAPIView, SubCategoryDetailAPIView, LanguageViewSet,
                    CourseListAPIView, CourseDetailAPIView, ChapterViewSet, NetworkStudentsViewSet,LessonAPIView, LessonDetailAPIView, AssignmentViewSet,
                    ExamDetailAPIView, ExamListAPIView, QuestionViewSet, OptionViewSet,CertificateAPIViewSet, ReviewViewSet, ReviewLikeViewSet, CourseCreateAPIView, CourseEditAPIView, RegisterView, LoginView, LogoutView)

router = DefaultRouter()
router.register(r"users", UserProfileViewSet, basename="users")
router.register(r"teachers", TeacherViewSet, basename="teachers")
router.register(r"chapters", ChapterViewSet, basename="chapters")
router.register(r"assignments", AssignmentViewSet, basename="assignments")
router.register(r"questions", QuestionViewSet, basename="questions")
router.register(r"options", OptionViewSet, basename="options")
router.register(r"reviews", ReviewViewSet, basename="reviews")
router.register(r"review-likes", ReviewLikeViewSet, basename="review-likes")

urlpatterns = [
    path("", include(router.urls)),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('course/', CourseListAPIView.as_view(), name='course_list'),
    path('course/<int:pk>', CourseDetailAPIView.as_view(), name='course_detail'),
    path('lesson/', LessonAPIView.as_view(), name='lesson_list'),
    path('lesson/<int:pk>', LessonDetailAPIView.as_view(), name='lesson_detail'),
    path('exam/', ExamListAPIView.as_view(), name='exam_list'),
    path('exam/<int:pk>', ExamDetailAPIView.as_view(), name='exam_detail'),
    path('category/', CategoryListAPIView.as_view(), name='category_list'),
    path('category/<int:pk>', CategoryDetailAPIView.as_view(), name='category_detail'),
    path('subcategory/', SubCategoryListAPIView.as_view(), name='sub_category_list'),
    path('subcategory/<int:pk>', SubCategoryDetailAPIView.as_view(), name='sub_category_detail'),
    path('my_certificate/', CertificateAPIViewSet.as_view(), name='my_certificate'),
    path('course/create/', CourseCreateAPIView.as_view(), name='course_create'),
    path('course/<int:pk>/edit/', CourseEditAPIView.as_view(), name='course_edit'),

]