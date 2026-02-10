from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator
from phonenumber_field.modelfields import PhoneNumberField

RoleChoices = (
('student', 'student'),
('teacher', 'teacher')
)

class UserProfile(AbstractUser):
    profile_picture = models.ImageField(upload_to='user_photo/')
    role = models.CharField(max_length=20, choices=RoleChoices, null=True, blank=True)
    age = models.PositiveIntegerField(validators=[MinValueValidator(18), MaxValueValidator(80)], null=True, blank=True)


class Teacher(UserProfile):
    bio = models.TextField()
    phone_number = PhoneNumberField()

    class Meta:
        verbose_name = "Teacher"
        verbose_name_plural = "Teacher"

class NetworkTeachers(models.Model):
    teacher = models.ForeignKey(Teacher, on_delete=models.CASCADE, related_name='networks')
    network_name = models.CharField(max_length=32)
    network_url = models.URLField()


class Category(models.Model):
    category_name = models.CharField(max_length=64, unique=True)

    def __str__(self):
        return self.category_name


class SubCategory(models.Model):
    subcategory_name = models.CharField(max_length=64, unique=True)
    teacher = models.ForeignKey(Teacher, on_delete=models.CASCADE, null=True, blank=True)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='sub_category')

    def __str__(self):
        return self.subcategory_name


class Language(models.Model):
    language_name = models.CharField(max_length=32, unique=True)

    def __str__(self):
        return self.language_name


class Course(models.Model):
    course_name = models.CharField(max_length=100)
    description = models.TextField()
    subcategory = models.ManyToManyField(SubCategory, related_name='course_sub')
    LevelChoices = (
    ('easy', 'easy'),
    ('medum', 'medum'),
    ('advensed', 'advensed')
    )
    level = models.CharField(max_length=32, choices=LevelChoices)
    price = models.DecimalField(max_digits=8, decimal_places=2)
    created_by = models.ForeignKey(Teacher, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    language = models.ManyToManyField(Language)
    course_photo = models.ImageField(upload_to='course_photo/')
    is_certificate = models.BooleanField(default=False)

    def __str__(self):
        return f'{self.course_name} {self.price}'

    def get_avg_rating(self):
        rating = self.rating_course.all()
        if rating.exists():
            return round(sum(i.ratting for i in rating) / rating.count(), 2)
        return 0

    def get_count_people(self):
        return self.rating_course.count()

    def get_student_count(self):
        return self.course_student.count()


class Chapter(models.Model):
    chapter_name = models.CharField(max_length=120)
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='chapters')

    def __str__(self):
        return self.chapter_name

    def get_lessons_count(self):
        return self.chapter_lesson.count()


class Student(models.Model):
    user = models.OneToOneField(UserProfile, on_delete=models.CASCADE)
    course = models.ForeignKey(Course, on_delete=models.CASCADE, null=True, blank=True, related_name='course_student')

    def __str__(self):
        return self.user.first_name


class NetworkStudents(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    network_name = models.CharField(max_length=32)
    network_url = models.URLField()


class Lesson(models.Model):
    lesson_name = models.CharField(max_length=120)
    lesson_image = models.ImageField(upload_to='lesson_photo/')
    lesson_file = models.FileField(upload_to='lesson_file/', null=True, blank=True)
    content = models.TextField()
    lesson_video = models.FileField(upload_to='lesson_video/', null=True, blank=True)
    chapter = models.ForeignKey(Chapter, on_delete=models.CASCADE, related_name='chapter_lesson')
    has_assignment = models.BooleanField(default=True)

    def __str__(self):
        return f'{self.lesson_name}{self.chapter}'


class Assignment(models.Model):
    assignment_name = models.CharField(max_length=64)
    description = models.TextField()
    lesson = models.ForeignKey(Lesson, on_delete=models.CASCADE, related_name='lesson_assignment')
    due_date = models.DateTimeField(verbose_name='Дедлайн')
    student = models.ForeignKey(Student, on_delete=models.CASCADE)

    def __str__(self):
        return f'{self.assignment_name} {self.lesson}'


class Exam(models.Model):
    chapter = models.ForeignKey(Chapter, on_delete=models.CASCADE, related_name='chapter_exam')
    exam_name = models.CharField(max_length=64)
    duration = models.DurationField()

    def __str__(self):
        return f'{self.chapter}{self.exam_name}'

    def get_question_count(self):
        return self.question_exam.count()

    def get_total_score(self):
        total = self.question_exam.all()
        if total.exists():
            return sum(i.score for i in total)
        return 0



class Question(models.Model):
    exam = models.ForeignKey(Exam, on_delete=models.CASCADE, related_name='question_exam')
    question_name = models.CharField(max_length=150)
    score = models.PositiveIntegerField(choices=[(i, str(i)) for i in range(1, 6)])


class Option(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name='option_ques')
    option_name = models.CharField(max_length=150, verbose_name='Вариант')
    option_type = models.BooleanField()


class Certificate(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='course_certificate')
    certificate_url = models.FileField(upload_to='certificate_url')
    issued_at  = models.DateField(auto_now_add=True)


class Review(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='rating_course')
    ratting = models.PositiveSmallIntegerField(choices=[(i, str(i)) for i in range(1, 6)],
                                               null=True, blank=True)
    text = models.TextField(null=True, blank=True)
    created_date = models.DateField(auto_now_add=True)

    def get_likes(self):
        like = self.review_like.all()
        if like.exists():
            return sum(i.like for i in like)
        return 0

    def get_dis_likes(self):
        like = self.review_like.all()
        if like.exists():
            return sum(i.dislike for i in like)
        return 0


class ReviewLike(models.Model):
    review = models.ForeignKey(Review, on_delete=models.CASCADE, related_name='review_like')
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    like = models.BooleanField(default=False)
    dislike = models.BooleanField(default=False)
    created_date = models.DateTimeField(auto_now_add=True)