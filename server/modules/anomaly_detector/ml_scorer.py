import numpy as np
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    """
    Detects behavioral anomalies in API traffic (e.g. BOLA attempts, 
    scraping, unusual patterns) using Isolation Forest.
    """
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.is_trained = False

    def train(self, historical_data: list):
        """
        Trains the model on historical features.
        Features: [request_length, response_time, entropy, params_count]
        """
        if len(historical_data) < 10:
            return  # Not enough data to train
        
        X = np.array(historical_data)
        self.model.fit(X)
        self.is_trained = True

    def predict(self, current_features: list) -> bool:
        """
        Returns True if the current request is an anomaly.
        """
        if not self.is_trained:
            return False
            
        X = np.array([current_features])
        prediction = self.model.predict(X)
        return prediction[0] == -1  # -1 is an outlier/anomaly
