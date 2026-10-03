.PHONY: install run test lint clean help

install:
	pip install -r requirements.txt

run:
	uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
	@echo ""
	@echo "✅ AI-SecOps Pipeline is running!"
	@echo "🌐 Dashboard   : http://localhost:8000"
	@echo "📋 Audit Log   : http://localhost:8000/audit"
	@echo "🔍 OWASP Scan  : http://localhost:8000/scanner"
	@echo "📚 API Docs    : http://localhost:8000/docs"

build-rag:
	python -c "from src.rag.rag_engine import build_vector_store; build_vector_store(force_rebuild=True)"
	@echo "✅ Vector store built from runbooks"

test:
	python -m pytest tests/ -v --tb=short

lint:
	flake8 src/ tests/ --max-line-length=120 --ignore=E501,W503,E226,E231 --count --statistics

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete 2>/dev/null; true
	rm -rf vector_store/ reports/ .pytest_cache/ 2>/dev/null; true
	@echo "🧹 Cleaned up"

help:
	@echo ""
	@echo "AI-SecOps Pipeline — Commands"
	@echo "=============================="
	@echo "  make install    Install Python dependencies"
	@echo "  make run        Start the web server"
	@echo "  make build-rag  Build FAISS vector store from runbooks"
	@echo "  make test       Run test suite"
	@echo "  make lint       Run flake8 linter"
	@echo "  make clean      Remove cache and build artifacts"
	@echo ""
