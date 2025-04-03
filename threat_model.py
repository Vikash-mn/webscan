import torch
import torch.nn as nn
from sklearn.feature_extraction.text import TfidfVectorizer
import pickle

class ThreatModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.layers = nn.Sequential(
            nn.Linear(1000, 512),
            nn.ReLU(),
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Linear(256, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        return self.layers(x)

# Load trained model
model = ThreatModel()
model.load_state_dict(torch.load('threat_model.pt'))
vectorizer = pickle.load(open('tfidf.pkl', 'rb'))

def predict_threat(url: str, html: str) -> float:
    features = vectorizer.transform([html])
    tensor = torch.FloatTensor(features.toarray())
    return model(tensor).item()