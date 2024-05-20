from django.shortcuts import render


def home(request):
      context = {
            'home': home,
      }
      return render(request, 'home.html', context)