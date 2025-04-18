# URL Detector Models

from models.few_shot import DeepSeekFewShot, ChatGPTFewShot, GeminiFewShot, LlamaFewShot
from models.chain_of_thought import DeepSeekChainOfThought, ChatGPTChainOfThought

# Function to get the appropriate model based on model type and technique
def get_model(model_type, technique):
    if model_type == "deepseek":
        if technique == "few-shot":
            return DeepSeekFewShot()
        elif technique == "chain-of-thought":
            return DeepSeekChainOfThought()
    elif model_type == "chatgpt":
        if technique == "few-shot":
            return ChatGPTFewShot()
        elif technique == "chain-of-thought":
            return ChatGPTChainOfThought()
    elif model_type == "gemini":
        if technique == "few-shot":
            return GeminiFewShot()
    elif model_type == "llama":
        if technique == "few-shot":
            return LlamaFewShot()
    
    # Default to DeepSeekFewShot if model type or technique is not recognized
    return DeepSeekFewShot()

# This file is a placeholder for your ML models
# In a real application, you would load your trained models here
# and expose functions to use them for detection 