from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
import asyncio
import aiohttp
import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import tldextract
from emergentintegrations.llm.chat import LlmChat, UserMessage
import json

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# LLM Integration
EMERGENT_LLM_KEY = os.environ.get('EMERGENT_LLM_KEY')

# Define Models
class URLAnalysisRequest(BaseModel):
    url: str
    user_id: Optional[str] = None

class PhishingResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: str
    is_phishing: bool
    confidence_score: float
    risk_level: str  # low, medium, high, critical
    analysis_details: Dict[str, Any]
    features_extracted: Dict[str, Any]
    ml_prediction: Dict[str, Any]
    nlp_analysis: Dict[str, Any]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    processing_time: float
    user_id: Optional[str] = None

class AlertEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: str
    risk_level: str
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: Optional[str] = None

class URLFeatures(BaseModel):
    url_length: int
    domain_age_days: int
    subdomain_count: int
    path_depth: int
    has_ip_address: bool
    has_suspicious_keywords: bool
    ssl_certificate: bool
    redirect_count: int
    domain_reputation: str

class PhishingAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            'verify', 'urgent', 'suspended', 'limited', 'expired', 'update',
            'confirm', 'secure', 'immediate', 'click', 'account', 'security',
            'login', 'password', 'bank', 'paypal', 'amazon', 'microsoft',
            'netflix', 'facebook', 'google', 'winner', 'congratulations'
        ]
        
        self.phishing_patterns = [
            r'bit\.ly', r'tinyurl', r't\.co', r'goo\.gl',
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
            r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.',  # suspicious subdomains
        ]

    async def analyze_url_safely(self, url: str) -> Dict[str, Any]:
        """Analyze URL in sandbox environment"""
        try:
            # Validate URL
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL format")

            # Extract domain features
            domain_info = tldextract.extract(url)
            
            # Initialize session with timeout and headers
            timeout = aiohttp.ClientTimeout(total=10)
            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            }
            
            content = ""
            response_headers = {}
            status_code = 0
            redirect_count = 0
            
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                try:
                    async with session.get(url, allow_redirects=True) as response:
                        status_code = response.status
                        response_headers = dict(response.headers)
                        redirect_count = len(response.history)
                        
                        if response.status == 200:
                            content_type = response.headers.get('content-type', '')
                            if 'text/html' in content_type:
                                content = await response.text(encoding='utf-8', errors='ignore')
                                content = content[:50000]  # Limit content size
                                
                except Exception as e:
                    logging.warning(f"Error fetching URL content: {str(e)}")
            
            return {
                'content': content,
                'status_code': status_code,
                'headers': response_headers,
                'redirect_count': redirect_count,
                'domain_info': {
                    'domain': domain_info.domain,
                    'subdomain': domain_info.subdomain,
                    'suffix': domain_info.suffix,
                    'registered_domain': domain_info.registered_domain
                }
            }
            
        except Exception as e:
            logging.error(f"Sandbox analysis error: {str(e)}")
            return {
                'error': str(e),
                'content': '',
                'status_code': 0,
                'headers': {},
                'redirect_count': 0
            }

    def extract_features(self, url: str, sandbox_data: Dict[str, Any]) -> URLFeatures:
        """Extract features for ML model"""
        parsed = urlparse(url)
        domain_info = sandbox_data.get('domain_info', {})
        
        # URL length
        url_length = len(url)
        
        # Check for IP address
        has_ip = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc))
        
        # Subdomain count
        subdomain = domain_info.get('subdomain', '')
        subdomain_count = len(subdomain.split('.')) if subdomain else 0
        
        # Path depth
        path_depth = len([p for p in parsed.path.split('/') if p])
        
        # Suspicious keywords in URL
        url_lower = url.lower()
        has_suspicious = any(keyword in url_lower for keyword in self.suspicious_keywords)
        
        # SSL certificate (basic check)
        ssl_certificate = parsed.scheme == 'https'
        
        # Redirect count
        redirect_count = sandbox_data.get('redirect_count', 0)
        
        return URLFeatures(
            url_length=url_length,
            domain_age_days=30,  # Placeholder - would need external API
            subdomain_count=subdomain_count,
            path_depth=path_depth,
            has_ip_address=has_ip,
            has_suspicious_keywords=has_suspicious,
            ssl_certificate=ssl_certificate,
            redirect_count=redirect_count,
            domain_reputation="unknown"
        )

    async def nlp_analysis(self, content: str, url: str) -> Dict[str, Any]:
        """Perform NLP analysis using LLM"""
        if not content.strip():
            return {
                'sentiment': 'neutral',
                'entities': [],
                'classification': 'unknown',
                'confidence': 0.0,
                'suspicious_elements': []
            }

        try:
            # Initialize LLM chat
            chat = LlmChat(
                api_key=EMERGENT_LLM_KEY,
                session_id=f"phishing_analysis_{uuid.uuid4()}",
                system_message="""You are an expert cybersecurity analyst specializing in phishing detection. 
                Analyze web content for phishing indicators and respond in JSON format only."""
            ).with_model("openai", "gpt-4o-mini")

            # Clean content for analysis
            if len(content) > 8000:
                soup = BeautifulSoup(content, 'html.parser')
                text_content = soup.get_text()[:4000]
            else:
                soup = BeautifulSoup(content, 'html.parser')
                text_content = soup.get_text()

            analysis_prompt = f"""
            Analyze this web content for phishing indicators:
            URL: {url}
            Content: {text_content[:3000]}

            Provide analysis in this exact JSON format:
            {{
                "is_phishing": true/false,
                "confidence": 0.0-1.0,
                "sentiment": "positive/negative/neutral",
                "classification": "legitimate/suspicious/phishing",
                "entities": ["list", "of", "extracted", "entities"],
                "suspicious_elements": ["list", "of", "suspicious", "elements"],
                "reasoning": "brief explanation of the decision"
            }}
            """

            user_message = UserMessage(text=analysis_prompt)
            response = await chat.send_message(user_message)
            
            # Parse JSON response
            try:
                result = json.loads(response)
                return result
            except json.JSONDecodeError:
                # Fallback if JSON parsing fails
                return {
                    'sentiment': 'neutral',
                    'entities': [],
                    'classification': 'unknown',
                    'confidence': 0.5,
                    'suspicious_elements': [],
                    'is_phishing': False,
                    'reasoning': 'Analysis failed to parse'
                }

        except Exception as e:
            logging.error(f"NLP analysis error: {str(e)}")
            return {
                'sentiment': 'neutral',
                'entities': [],
                'classification': 'error',
                'confidence': 0.0,
                'suspicious_elements': [],
                'error': str(e)
            }

    def calculate_ml_score(self, features: URLFeatures, nlp_result: Dict[str, Any]) -> Dict[str, Any]:
        """Hybrid ML scoring combining traditional features and NLP"""
        score = 0.0
        factors = []

        # URL-based scoring
        if features.url_length > 100:
            score += 0.2
            factors.append("Long URL")
        
        if features.has_ip_address:
            score += 0.3
            factors.append("IP address in URL")
        
        if features.subdomain_count > 2:
            score += 0.15
            factors.append("Multiple subdomains")
        
        if features.has_suspicious_keywords:
            score += 0.25
            factors.append("Suspicious keywords")
        
        if not features.ssl_certificate:
            score += 0.1
            factors.append("No SSL certificate")
        
        if features.redirect_count > 2:
            score += 0.2
            factors.append("Multiple redirects")

        # NLP-based scoring
        nlp_confidence = nlp_result.get('confidence', 0.0)
        if nlp_result.get('is_phishing', False):
            score += nlp_confidence * 0.4
            factors.append("NLP detected phishing")
        
        if nlp_result.get('classification') == 'suspicious':
            score += 0.15
            factors.append("Suspicious content detected")

        # Normalize score
        score = min(score, 1.0)

        return {
            'phishing_score': score,
            'contributing_factors': factors,
            'model_version': '1.0',
            'feature_weights': {
                'url_features': 0.6,
                'nlp_analysis': 0.4
            }
        }

    def determine_risk_level(self, score: float) -> str:
        """Determine risk level based on score"""
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        else:
            return "low"

# Initialize analyzer
analyzer = PhishingAnalyzer()

# API Routes
@api_router.post("/analyze", response_model=PhishingResult)
async def analyze_url(request: URLAnalysisRequest, background_tasks: BackgroundTasks):
    """Analyze URL for phishing indicators"""
    start_time = datetime.now(timezone.utc)
    
    try:
        # Sandbox analysis
        sandbox_data = await analyzer.analyze_url_safely(request.url)
        
        # Feature extraction
        features = analyzer.extract_features(request.url, sandbox_data)
        
        # NLP analysis
        nlp_result = await analyzer.nlp_analysis(sandbox_data.get('content', ''), request.url)
        
        # ML prediction
        ml_prediction = analyzer.calculate_ml_score(features, nlp_result)
        
        # Final decision
        confidence_score = ml_prediction['phishing_score']
        is_phishing = confidence_score >= 0.6
        risk_level = analyzer.determine_risk_level(confidence_score)
        
        # Processing time
        processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        # Create result
        result = PhishingResult(
            url=request.url,
            is_phishing=is_phishing,
            confidence_score=confidence_score,
            risk_level=risk_level,
            analysis_details={
                'sandbox_analysis': {
                    'status_code': sandbox_data.get('status_code'),
                    'redirect_count': sandbox_data.get('redirect_count'),
                    'content_length': len(sandbox_data.get('content', ''))
                },
                'domain_info': sandbox_data.get('domain_info', {}),
                'timestamp': start_time.isoformat()
            },
            features_extracted=features.dict(),
            ml_prediction=ml_prediction,
            nlp_analysis=nlp_result,
            processing_time=processing_time,
            user_id=request.user_id
        )
        
        # Store result in database
        await db.phishing_results.insert_one(result.dict())
        
        # Create alert if high risk
        if risk_level in ['high', 'critical']:
            alert = AlertEntry(
                url=request.url,
                risk_level=risk_level,
                message=f"High-risk phishing site detected with {confidence_score:.2%} confidence",
                user_id=request.user_id
            )
            await db.alerts.insert_one(alert.dict())
            
        return result
        
    except Exception as e:
        logging.error(f"Analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@api_router.get("/results", response_model=List[PhishingResult])
async def get_analysis_results(limit: int = 50, user_id: Optional[str] = None):
    """Get analysis results history"""
    query = {}
    if user_id:
        query['user_id'] = user_id
    
    results = await db.phishing_results.find(query).sort("timestamp", -1).limit(limit).to_list(limit)
    return [PhishingResult(**result) for result in results]

@api_router.get("/alerts", response_model=List[AlertEntry])
async def get_alerts(limit: int = 20, user_id: Optional[str] = None):
    """Get recent alerts"""
    query = {}
    if user_id:
        query['user_id'] = user_id
    
    alerts = await db.alerts.find(query).sort("timestamp", -1).limit(limit).to_list(limit)
    return [AlertEntry(**alert) for alert in alerts]

@api_router.get("/stats")
async def get_statistics(user_id: Optional[str] = None):
    """Get analysis statistics"""
    query = {}
    if user_id:
        query['user_id'] = user_id
    
    total_analyses = await db.phishing_results.count_documents(query)
    phishing_detected = await db.phishing_results.count_documents({**query, "is_phishing": True})
    
    # Risk level distribution
    risk_levels = await db.phishing_results.aggregate([
        {"$match": query},
        {"$group": {"_id": "$risk_level", "count": {"$sum": 1}}}
    ]).to_list(None)
    
    risk_distribution = {item['_id']: item['count'] for item in risk_levels}
    
    # Recent activity (last 7 days)
    from datetime import timedelta
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    recent_analyses = await db.phishing_results.count_documents({
        **query, 
        "timestamp": {"$gte": week_ago}
    })
    
    return {
        'total_analyses': total_analyses,
        'phishing_detected': phishing_detected,
        'detection_rate': phishing_detected / total_analyses if total_analyses > 0 else 0,
        'risk_distribution': risk_distribution,
        'recent_activity': recent_analyses
    }

@api_router.delete("/results/{result_id}")
async def delete_result(result_id: str):
    """Delete analysis result"""
    result = await db.phishing_results.delete_one({"id": result_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Result not found")
    return {"message": "Result deleted successfully"}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()