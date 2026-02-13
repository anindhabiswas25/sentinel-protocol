import google.generativeai as genai

genai.configure(api_key='AIzaSyBmEFzrrb0bnPxM686fO0j-U3zuUrEH3Eo')

print("Available Gemini models that support generateContent:\n")
for m in genai.list_models():
    if 'generateContent' in m.supported_generation_methods:
        print(f"  ✅ {m.name}")
