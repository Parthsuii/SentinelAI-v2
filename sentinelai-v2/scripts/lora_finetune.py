"""
SentinelAI v2.0 — LoRA Fine-Tuning Pipeline
Reads user feedback from SQLite and fine-tunes the base SLMs (e.g. smollm2) using PEFT/LoRA.
Triggered monthly or when feedback_count >= 500.
"""

import os
import sqlite3
import json
import torch
from peft import LoraConfig, get_peft_model, TaskType
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments, Trainer
from datasets import Dataset

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "sentinel.db")
BASE_MODEL = "HuggingFaceTB/SmolLM2-0.35B-Instruct"  # Base model for url-agent v3
OUTPUT_DIR = "./data/models/sentinel-url-lora"


def load_feedback_data(db_path: str, min_samples: int = 500) -> list:
    """Load and format user feedback from SQLite for training."""
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return []

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM user_feedback").fetchall()

    if len(rows) < min_samples:
        print(f"Not enough feedback data ({len(rows)} < {min_samples}). Skipping fine-tuning.")
        return []

    dataset = []
    for row in rows:
        url = row["url"]
        is_correct = bool(row["is_correct"])
        feedback = row["feedback"]
        
        # Format into a simple prompt-completion pair for causal LM
        prompt = f"Analyze this URL for phishing/malware indicators: {url}\n"
        completion = f"Feedback: {feedback}. Original prediction was {'correct' if is_correct else 'incorrect'}."
        
        dataset.append({
            "text": prompt + completion
        })

    return dataset


def run_lora_finetune():
    """Execute PEFT/LoRA fine-tuning on the local GPU."""
    print("🛡️ SentinelAI v3.0 — Starting LoRA Fine-Tuning Pipeline")
    
    data = load_feedback_data(DB_PATH, min_samples=200) # v3 threshold Drop from 500 to 200
    if not data:
        return

    print(f"Loaded {len(data)} training samples. Preparing model...")

    try:
        tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
        tokenizer.pad_token = tokenizer.eos_token
        
        model = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL,
            torch_dtype=torch.float16,
            device_map="auto"
        )

        peft_config = LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=8,
            lora_alpha=32,
            lora_dropout=0.1,
            target_modules=["q_proj", "v_proj"]
        )

        model = get_peft_model(model, peft_config)
        model.print_trainable_parameters()

        # Convert to HuggingFace Dataset
        hf_dataset = Dataset.from_list(data)
        
        def tokenize_function(examples):
            return tokenizer(examples["text"], padding="max_length", truncation=True, max_length=128)

        tokenized_datasets = hf_dataset.map(tokenize_function, batched=True)

        training_args = TrainingArguments(
            output_dir=OUTPUT_DIR,
            per_device_train_batch_size=4,
            gradient_accumulation_steps=4,
            learning_rate=2e-4,
            num_train_epochs=3,
            logging_steps=10,
            save_strategy="epoch",
            fp16=True,
            optim="adamw_torch"
        )

        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=tokenized_datasets,
            data_collator=lambda x: tokenizer.pad(x, return_tensors="pt")
        )

        print("Starting training loop...")
        trainer.train()

        print(f"Training complete. Saving adapter weights to {OUTPUT_DIR}")
        model.save_pretrained(OUTPUT_DIR)
        
        # Clear feedback table after training
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM user_feedback")
            print("Cleared feedback buffer.")

    except Exception as e:
        print(f"LoRA fine-tuning failed: {e}")


if __name__ == "__main__":
    run_lora_finetune()
