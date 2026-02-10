from modeltranslation.translator import register, TranslationOptions
from .models import (NetworkTeachers, NetworkStudents, Category,
                     SubCategory, Language, Course, Chapter, Lesson,
                     Assignment, Exam, Question, Option)


@register(NetworkStudents)
class NetworkStudentsTranslationOptions(TranslationOptions):
    fields = ('network_name',)

@register(NetworkTeachers)
class NetworkTeachersTranslationOptions(TranslationOptions):
    fields = ('network_name',)

@register(Category)
class CategoryTranslationOptions(TranslationOptions):
    fields = ('category_name',)

@register(SubCategory)
class SubCategoryTranslationOptions(TranslationOptions):
    fields = ('subcategory_name',)

@register(Language)
class LanguageTranslationOptions(TranslationOptions):
    fields = ('language_name',)

@register(Chapter)
class ChapterTranslationOptions(TranslationOptions):
    fields = ('chapter_name',)

@register(Course)
class CourseTranslationOptions(TranslationOptions):
    fields = ('course_name', 'description')

@register(Lesson)
class LessonTranslationOptions(TranslationOptions):
    fields = ('lesson_name', 'content')


@register(Assignment)
class AssignmentTranslationOptions(TranslationOptions):
    fields = ('assignment_name', 'description')


@register(Exam)
class ExamTranslationOptions(TranslationOptions):
    fields = ('exam_name',)


@register(Question)
class QuestionTranslationOptions(TranslationOptions):
    fields = ('question_name',)


@register(Option)
class OptionTranslationOptions(TranslationOptions):
    fields = ('option_name',)