"""
Was written in Python Version 3.10.6 by ENG Chanveasna
This AI model is from https://huggingface.co/rdpahalavan/bert-network-packet-flow-header-payload
"""


from transformers import AutoTokenizer, AutoModelForSequenceClassification


class NetworkDetectionModel:
    CLASS_LABELS = [
        'Analysis',
        'Backdoor',
        'Bot',
        'DDoS',
        'DoS',
        'DoS GoldenEye',
        'DoS Hulk',
        'DoS SlowHTTPTest',
        'DoS Slowloris',
        'Exploits',
        'FTP Patator',
        'Fuzzers',
        'Generic',
        'Heartbleed',
        'Infiltration',
        'Normal',
        'Port Scan',
        'Reconnaissance',
        'SSH Patator',
        'Shellcode',
        'Web Attack - Brute Force',
        'Web Attack - SQL Injection',
        'Web Attack - XSS',
        'Worms'
    ]

    def __init__(self):
        self.tokenizer = AutoTokenizer.from_pretrained(
            "rdpahalavan/bert-network-packet-flow-header-payload")
        self.model = AutoModelForSequenceClassification.from_pretrained(
            "rdpahalavan/bert-network-packet-flow-header-payload")

    # def predict(self, sequence: str) -> str:
    #     # Tokenize the sequence
    #     inputs = self.tokenizer(sequence, return_tensors="pt")

    #     # Perform the classification
    #     outputs = self.model(**inputs)

    #     # The model returns first element with highest probability
    #     logits = outputs[0]

    #     # To get the predicted class
    #     predicted_class_index = logits.argmax(dim=-1).item()
    #     predicted_class_label = self.CLASS_LABELS[predicted_class_index]

    #     return predicted_class_label

    def predict(self, sequence: str) -> str:
        # Tokenize the sequence
        tokens = self.tokenizer.tokenize(sequence)

        # Ensure the number of tokens doesn't exceed the maximum
        MAX_TOKENS = 512 - 2  # subtract 2 for [CLS] and [SEP]
        tokens = tokens[:MAX_TOKENS]

        # Convert the tokens back to a string
        sequence = self.tokenizer.convert_tokens_to_string(tokens)

        # Tokenize the sequence again, this time with return_tensors="pt"
        inputs = self.tokenizer(sequence, return_tensors="pt")

        # Perform the classification
        outputs = self.model(**inputs)

        # The model returns first element with highest probability
        logits = outputs[0]

        # To get the predicted class
        predicted_class_index = logits.argmax(dim=-1).item()
        predicted_class_label = self.CLASS_LABELS[predicted_class_index]

        return predicted_class_label


"""
Usage :
model = NetworkDetectionModel()
model.predict("your sequence here")
"""
