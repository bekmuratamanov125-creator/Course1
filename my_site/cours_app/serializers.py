from rest_framework import serializers
from .models import (UserProfile, Teacher, NetworkTeachers, Category, SubCategory, Language, Course, Chapter,Student, NetworkStudents,
                     Lesson, Assignment,Exam, Question, Option,Certificate, Review, ReviewLike)
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate


class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ('username', 'email', 'password', 'first_name', 'last_name')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = UserProfile.objects.create_user(**validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(**data)
        if user and user.is_active:
            return user
        raise serializers.ValidationError("Неверные учетные данные")

    def to_representation(self, instance):
        refresh = RefreshToken.for_user(instance)
        return {
            'user': {
                'username': instance.username,
                'email': instance.email,
            },
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = "__all__"

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['first_name']


class TeacherSerializer(serializers.ModelSerializer):
    class Meta:
        model = Teacher
        fields = "__all__"

class TeacherNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Teacher
        fields = ['id', 'first_name', 'last_name']


class NetworkTeachersSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkTeachers
        fields = ['network_name', 'network_url']


class TeacherNameDetailSerializer(serializers.ModelSerializer):
    networks = NetworkTeachersSerializer(read_only=True, many=True)
    class Meta:
        model = Teacher
        fields = ['id', 'first_name', 'last_name', 'bio', 'networks']


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['category_name']


class CategoryListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'category_name']


class SubCategoryListSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubCategory
        fields = ['id', 'subcategory_name']


class CategoryDetailSerializer(serializers.ModelSerializer):
    sub_category = SubCategoryListSerializer(many=True, read_only=True)
    class Meta:
        model = Category
        fields = ['category_name', 'sub_category']



class SubCategorySerializer(serializers.ModelSerializer):
    sub_category = CategorySerializer(read_only=True, many=True)
    class Meta:
        model = SubCategory
        fields = ['sub_category', 'subcategory_name']


class LanguageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Language
        fields = ['language_name']


class CourseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = ['id', 'course_name']

class CourseCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = '__all__'


class CourseListSerializer(serializers.ModelSerializer):
    language = LanguageSerializer(many=True)
    created_by = TeacherNameSerializer()
    avg_rating = serializers.SerializerMethodField()
    count_people = serializers.SerializerMethodField()
    student_count = serializers.SerializerMethodField()
    class Meta:
        model = Course
        fields = ['id', 'course_name', 'description', 'level', 'language', 'price', 'avg_rating', 'count_people',
                  'student_count', 'created_by', 'course_photo', 'is_certificate']

    def get_avg_rating(self, obj):
        return obj.get_avg_rating()

    def get_count_people(self, obj):
        return obj.get_count_people()

    def get_student_count(self, obj):
        return obj.get_student_count()


class SubCategoryDetailSerializer(serializers.ModelSerializer):
    course_sub = CourseListSerializer(many=True, read_only=True)
    class Meta:
        model = SubCategory
        fields = ['subcategory_name', 'course_sub']


class StudentNameSerializer(serializers.ModelSerializer):
    user = UserSerializer()
    class Meta:
        model = Student
        fields = ['user']


class NetworkStudentsSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkStudents
        fields = "__all__"


class LessonSerializer(serializers.ModelSerializer):
    class Meta:
        model = Lesson
        fields = ['id', 'lesson_name', 'lesson_image', 'lesson_file', 'lesson_video', 'content', 'has_assignment']


class AssignmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Assignment
        fields = ['id', 'assignment_name', 'description', 'due_date']


class ExamSerializer(serializers.ModelSerializer):
    class Meta:
        model = Exam
        fields = ['id', 'exam_name', 'duration']


class ExamListSerializer(serializers.ModelSerializer):
    question_count = serializers.SerializerMethodField()
    total_score = serializers.SerializerMethodField()
    class Meta:
        model = Exam
        fields = ['id', 'exam_name', 'duration', 'question_count', 'total_score']

    def get_question_count(self, obj):
        return obj.get_question_count()

    def get_total_score(self, obj):
        return obj.get_total_score()


class OptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Option
        fields = ['id', 'option_name']


class QuestionSerializer(serializers.ModelSerializer):
    option_ques = OptionSerializer(read_only=True, many=True)
    class Meta:
        model = Question
        fields = ['id', 'question_name', 'score', 'option_ques']



class ExamDetailSerializer(serializers.ModelSerializer):
    question_exam = QuestionSerializer(read_only=True, many=True)

    class Meta:
        model = Exam
        fields = ['id', 'exam_name', 'duration', 'question_exam']


class LessonDetailSerializer(serializers.ModelSerializer):
    lesson_assignment = AssignmentSerializer(read_only=True, many=True)
    class Meta:
        model = Lesson
        fields = ['id', 'lesson_name', 'lesson_image', 'lesson_file', 'lesson_video', 'content', 'lesson_assignment']


class ChapterSerializer(serializers.ModelSerializer):
    chapter_lesson = LessonSerializer(read_only=True, many=True)
    chapter_exam = ExamSerializer(read_only=True, many=True)
    lessons_count = serializers.SerializerMethodField()
    class Meta:
        model = Chapter
        fields = ['id', 'chapter_name', 'lessons_count', 'chapter_lesson', 'chapter_exam']

    def get_lessons_count(self, obj):
        return obj.get_lessons_count()


class CertificateSerializer(serializers.ModelSerializer):
    course_certificate =  CourseSerializer(read_only=True, many=True)
    class Meta:
        model = Certificate
        fields = ['course_certificate', 'issued_at', 'certificate_url']


class ReviewSerializer(serializers.ModelSerializer):
    student = UserSerializer()
    dis_likes = serializers.SerializerMethodField()
    likes = serializers.SerializerMethodField()
    class Meta:
        model = Review
        fields = ['id', 'student', 'ratting', 'text', 'created_date', 'likes', 'dis_likes']

    def get_dis_likes(self, obj):
        return obj.get_dis_likes()

    def get_likes(self, obj):
        return obj.get_likes()


class ReviewLikeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReviewLike
        fields = "__all__"


class CourseDetailSerializer(serializers.ModelSerializer):
    language = LanguageSerializer(many=True)
    created_by = TeacherNameDetailSerializer()
    subcategory = SubCategorySerializer(many=True)
    chapters = ChapterSerializer(many=True, read_only=True)
    rating_course = ReviewSerializer(many=True, read_only=True)

    class Meta:
        model = Course
        fields = ['id', 'course_name', 'description', 'level', 'language', 'price', 'is_certificate',
                  'created_by', 'subcategory', 'chapters', 'rating_course']