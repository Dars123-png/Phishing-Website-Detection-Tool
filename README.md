# Phishing-Website-Detection-Tool

A lightweight Python application that detects phishing websites using both rule-based heuristics and a machine learning model, wrapped inside a colorful, user-friendly Tkinter GUI interface. This tool helps users avoid phishing scams by analyzing suspicious URLs and giving instant visual feedback.

Problem Statement
Phishing websites deceive users into entering sensitive information (e.g., passwords, credit card numbers), leading to identity theft and financial fraud.

Objective
Create a hybrid system that:

Detects potentially harmful URLs using custom rule-based logic.

Uses machine learning (ML) to learn and classify URLs based on features.

Provides a GUI with emojis and optional graphs to visualize results.
| Feature                   | Description                                                             |
| ------------------------- | ----------------------------------------------------------------------- |
| Rule-Based System      | Uses heuristics like IPs in URLs, `@`, suspicious keywords, URL length. |
| ML Classifier          | Trained using Scikit-learn (Random Forest / Decision Tree).             |
| URL Analyzer           | Extracts and analyzes components of the URL for red flags.              |
| GUI Interface          | Built with Tkinter, includes emojis and user input box.                 |
| Optional Visualization | Accuracy chart or confusion matrix via matplotlib/seaborn.              |
| Dataset Ready          | Tested on phishing + legitimate URLs from public datasets.              |

## 📦 Requirements

- Python 3.8+
- Install dependencies with:

bash
pip install -r requirements.txt
