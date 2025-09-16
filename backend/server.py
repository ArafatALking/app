from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks, UploadFile, File, Form
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, HttpUrl, EmailStr
from typing import List, Optional, Dict, Any, Union
import uuid
from datetime import datetime, timezone, timedelta
import asyncio
import aiohttp
import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import tldextract
from emergentintegrations.llm.chat import LlmChat, UserMessage
import json
import email
from email import policy
from email.parser import BytesParser
import base64

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

class EmailAnalysisRequest(BaseModel):
    sender: Optional[str] = None
    subject: Optional[str] = None
    content: str
    attachments: Optional[List[str]] = None
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

class EmailAnalysisResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sender: Optional[str] = None
    subject: Optional[str] = None
    is_phishing: bool
    confidence_score: float
    risk_level: str
    analysis_details: Dict[str, Any]
    urls_found: List[str] = []
    attachments_analysis: List[Dict[str, Any]] = []
    sender_reputation: Dict[str, Any] = {}
    nlp_analysis: Dict[str, Any]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    processing_time: float
    user_id: Optional[str] = None

class AlertEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: Optional[str] = None
    email_sender: Optional[str] = None
    alert_type: str  # url_threat, email_threat, suspicious_activity
    risk_level: str
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: Optional[str] = None

class BlacklistEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entry_type: str  # url, domain, email, ip
    value: str
    reason: str
    severity: str  # low, medium, high, critical
    added_by: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True

class SecurityIncident(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_type: str  # phishing_detected, malware_found, suspicious_email
    severity: str
    source: str  # url, email
    source_value: str
    description: str
    actions_taken: List[str] = []
    status: str = "open"  # open, investigating, resolved, closed
    assigned_to: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    user_id: Optional[str] = None

class QuarantinedItem(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    item_type: str  # url, email, attachment
    item_value: str
    reason: str
    risk_level: str
    quarantine_action: str  # blocked, isolated, flagged
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    release_date: Optional[datetime] = None
    user_id: Optional[str] = None

class ResponseAction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    trigger_type: str  # threat_detected, high_risk_score
    action_type: str  # blacklist_add, quarantine, notify_admin, block_user
    severity_threshold: str
    is_automated: bool = True
    is_active: bool = True
    created_by: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AdminSettings(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    notification_email: Optional[str] = None
    notification_sms: Optional[str] = None
    auto_quarantine_threshold: str = "high"  # medium, high, critical
    auto_blacklist_enabled: bool = True
    incident_auto_assignment: bool = False
    email_notifications_enabled: bool = True
    sms_notifications_enabled: bool = False
    updated_by: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

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

class SecurityManager:
    def __init__(self):
        self.suspicious_keywords = [
            'verify', 'urgent', 'suspended', 'limited', 'expired', 'update',
            'confirm', 'secure', 'immediate', 'click', 'account', 'security',
            'login', 'password', 'bank', 'paypal', 'amazon', 'microsoft',
            'netflix', 'facebook', 'google', 'winner', 'congratulations',
            'تأكيد', 'عاجل', 'موقوف', 'محدود', 'منتهي', 'تحديث',
            'فوري', 'امن', 'حساب', 'كلمة مرور', 'بنك', 'فائز'
        ]
        
        self.phishing_patterns = [
            r'bit\.ly', r'tinyurl', r't\.co', r'goo\.gl',
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
            r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.',  # suspicious subdomains
        ]

    async def check_blacklist(self, value: str, entry_type: str) -> Optional[BlacklistEntry]:
        """Check if value is in blacklist"""
        blacklist_entry = await db.blacklist.find_one({
            "value": value, 
            "entry_type": entry_type, 
            "is_active": True
        })
        return BlacklistEntry(**blacklist_entry) if blacklist_entry else None

    async def add_to_blacklist(self, value: str, entry_type: str, reason: str, severity: str, added_by: str):
        """Add entry to blacklist"""
        # Check if already exists
        existing = await self.check_blacklist(value, entry_type)
        if not existing:
            blacklist_entry = BlacklistEntry(
                entry_type=entry_type,
                value=value,
                reason=reason,
                severity=severity,
                added_by=added_by
            )
            await db.blacklist.insert_one(blacklist_entry.dict())
            return blacklist_entry
        return existing

    async def create_incident(self, incident_type: str, severity: str, source: str, 
                            source_value: str, description: str, user_id: str = None):
        """Create security incident"""
        incident = SecurityIncident(
            incident_type=incident_type,
            severity=severity,
            source=source,
            source_value=source_value,
            description=description,
            user_id=user_id
        )
        await db.incidents.insert_one(incident.dict())
        return incident

    async def quarantine_item(self, item_type: str, item_value: str, reason: str, 
                            risk_level: str, user_id: str = None):
        """Quarantine suspicious item"""
        quarantine_item = QuarantinedItem(
            item_type=item_type,
            item_value=item_value,
            reason=reason,
            risk_level=risk_level,
            quarantine_action="isolated",
            user_id=user_id
        )
        await db.quarantine.insert_one(quarantine_item.dict())
        return quarantine_item

    async def send_admin_notification(self, message: str, severity: str, source_data: Dict):
        """Send notification to administrators"""
        # Get admin settings
        admin_settings = await db.admin_settings.find_one()
        
        notification_data = {
            "message": message,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_data": source_data
        }
        
        # Store notification in database
        await db.notifications.insert_one(notification_data)
        
        # Here you would integrate with actual email/SMS services
        logging.info(f"Admin notification: {message} (Severity: {severity})")

    async def execute_response_actions(self, analysis_result: Union[PhishingResult, EmailAnalysisResult]):
        """Execute automated response actions based on threat level"""
        # Get active response actions
        response_actions = await db.response_actions.find({"is_active": True}).to_list(None)
        
        for action_config in response_actions:
            action = ResponseAction(**action_config)
            
            # Check if severity meets threshold
            severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            if severity_levels.get(analysis_result.risk_level, 0) >= severity_levels.get(action.severity_threshold, 4):
                
                if action.action_type == "blacklist_add":
                    if hasattr(analysis_result, 'url'):
                        await self.add_to_blacklist(
                            analysis_result.url, "url", 
                            f"Auto-blacklisted due to {analysis_result.risk_level} risk", 
                            analysis_result.risk_level, "system"
                        )
                    elif hasattr(analysis_result, 'sender') and analysis_result.sender:
                        await self.add_to_blacklist(
                            analysis_result.sender, "email", 
                            f"Auto-blacklisted due to {analysis_result.risk_level} risk", 
                            analysis_result.risk_level, "system"
                        )
                
                elif action.action_type == "quarantine":
                    if hasattr(analysis_result, 'url'):
                        await self.quarantine_item(
                            "url", analysis_result.url, 
                            f"Auto-quarantined due to {analysis_result.risk_level} risk",
                            analysis_result.risk_level, analysis_result.user_id
                        )
                    elif hasattr(analysis_result, 'sender'):
                        await self.quarantine_item(
                            "email", analysis_result.sender or "unknown", 
                            f"Auto-quarantined due to {analysis_result.risk_level} risk",
                            analysis_result.risk_level, analysis_result.user_id
                        )
                
                elif action.action_type == "notify_admin":
                    source_value = getattr(analysis_result, 'url', None) or getattr(analysis_result, 'sender', 'unknown')
                    await self.send_admin_notification(
                        f"High-risk threat detected: {source_value}",
                        analysis_result.risk_level,
                        {"analysis_id": analysis_result.id, "confidence": analysis_result.confidence_score}
                    )
                
                elif action.action_type == "incident_create":
                    source_value = getattr(analysis_result, 'url', None) or getattr(analysis_result, 'sender', 'unknown')
                    source_type = "url" if hasattr(analysis_result, 'url') else "email"
                    await self.create_incident(
                        "phishing_detected",
                        analysis_result.risk_level,
                        source_type,
                        source_value,
                        f"Automated incident creation for {analysis_result.risk_level} risk threat",
                        analysis_result.user_id
                    )

class PhishingAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            'verify', 'urgent', 'suspended', 'limited', 'expired', 'update',
            'confirm', 'secure', 'immediate', 'click', 'account', 'security',
            'login', 'password', 'bank', 'paypal', 'amazon', 'microsoft',
            'netflix', 'facebook', 'google', 'winner', 'congratulations',
            'تأكيد', 'عاجل', 'موقوف', 'محدود', 'منتهي', 'تحديث',
            'فوري', 'امن', 'حساب', 'كلمة مرور', 'بنك', 'فائز'
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

    async def analyze_email_content(self, sender: str, subject: str, content: str, user_id: str = None) -> EmailAnalysisResult:
        """Analyze email content for phishing indicators"""
        start_time = datetime.now(timezone.utc)
        
        # Extract URLs from email content
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"\']*'
        urls_found = re.findall(url_pattern, content)
        
        # Analyze sender domain
        sender_domain = ""
        sender_reputation = {"score": 0.5, "factors": []}
        
        if sender and "@" in sender:
            sender_domain = sender.split("@")[1]
            # Basic sender reputation check
            if any(keyword in sender_domain.lower() for keyword in ['temp', 'throwaway', '10minute']):
                sender_reputation["score"] = 0.2
                sender_reputation["factors"].append("Temporary email domain")
        
        # NLP analysis of email content
        nlp_result = await self.nlp_analysis(content + " " + (subject or ""), f"Email from {sender}")
        
        # Calculate risk score
        risk_score = 0.0
        risk_factors = []
        
        # Content-based factors
        if any(keyword in content.lower() for keyword in self.suspicious_keywords):
            risk_score += 0.3
            risk_factors.append("Suspicious keywords in content")
        
        if any(keyword in (subject or "").lower() for keyword in self.suspicious_keywords):
            risk_score += 0.2
            risk_factors.append("Suspicious keywords in subject")
        
        # URL-based factors
        if urls_found:
            risk_score += min(len(urls_found) * 0.1, 0.3)
            risk_factors.append(f"Contains {len(urls_found)} URLs")
        
        # Sender-based factors
        if sender_reputation["score"] < 0.3:
            risk_score += 0.2
            risk_factors.append("Low sender reputation")
        
        # NLP-based factors
        if nlp_result.get('is_phishing', False):
            risk_score += nlp_result.get('confidence', 0.0) * 0.4
            risk_factors.append("NLP detected phishing content")
        
        # Normalize score
        risk_score = min(risk_score, 1.0)
        
        # Determine risk level
        risk_level = self.determine_risk_level(risk_score)
        is_phishing = risk_score >= 0.6
        
        processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        result = EmailAnalysisResult(
            sender=sender,
            subject=subject,
            is_phishing=is_phishing,
            confidence_score=risk_score,
            risk_level=risk_level,
            analysis_details={
                "risk_factors": risk_factors,
                "urls_count": len(urls_found),
                "content_length": len(content),
                "processing_time": processing_time
            },
            urls_found=urls_found,
            sender_reputation=sender_reputation,
            nlp_analysis=nlp_result,
            processing_time=processing_time,
            user_id=user_id
        )
        
        return result

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

    async def nlp_analysis(self, content: str, source: str) -> Dict[str, Any]:
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
                Analyze content for phishing indicators and respond in JSON format only."""
            ).with_model("openai", "gpt-4o-mini")

            # Clean content for analysis
            text_content = content[:4000] if len(content) > 4000 else content

            analysis_prompt = f"""
            Analyze this content for phishing indicators:
            Source: {source}
            Content: {text_content}

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

# Initialize analyzers
analyzer = PhishingAnalyzer()
security_manager = SecurityManager()

# API Routes

# URL Analysis (existing)
@api_router.post("/analyze", response_model=PhishingResult)
async def analyze_url(request: URLAnalysisRequest, background_tasks: BackgroundTasks):
    """Analyze URL for phishing indicators"""
    start_time = datetime.now(timezone.utc)
    
    # Input validation
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=422, detail="URL is required and cannot be empty")
    
    url = request.url.strip()
    
    # Basic URL format validation
    if not url.startswith(('http://', 'https://')):
        raise HTTPException(status_code=422, detail="URL must start with http:// or https://")
    
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            raise HTTPException(status_code=422, detail="Invalid URL format")
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid URL format")
    
    try:
        # Check blacklist first
        blacklist_entry = await security_manager.check_blacklist(url, "url")
        if blacklist_entry:
            # Return immediate high-risk result for blacklisted URLs
            result = PhishingResult(
                url=url,
                is_phishing=True,
                confidence_score=0.95,
                risk_level="critical",
                analysis_details={"blacklisted": True, "reason": blacklist_entry.reason},
                features_extracted={},
                ml_prediction={"blacklist_hit": True},
                nlp_analysis={"classification": "blacklisted"},
                processing_time=0.01,
                user_id=request.user_id
            )
            await db.phishing_results.insert_one(result.dict())
            return result
        
        # Sandbox analysis
        sandbox_data = await analyzer.analyze_url_safely(url)
        
        # Feature extraction
        features = analyzer.extract_features(url, sandbox_data)
        
        # NLP analysis
        nlp_result = await analyzer.nlp_analysis(sandbox_data.get('content', ''), url)
        
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
            url=url,
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
        
        # Execute automated response actions
        background_tasks.add_task(security_manager.execute_response_actions, result)
        
        # Create alert if high risk
        if risk_level in ['high', 'critical']:
            alert = AlertEntry(
                url=url,
                alert_type="url_threat",
                risk_level=risk_level,
                message=f"High-risk phishing site detected with {confidence_score:.2%} confidence",
                user_id=request.user_id
            )
            await db.alerts.insert_one(alert.dict())
            
        return result
        
    except Exception as e:
        logging.error(f"Analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# Email Analysis (new)
@api_router.post("/email/analyze", response_model=EmailAnalysisResult)
async def analyze_email(request: EmailAnalysisRequest, background_tasks: BackgroundTasks):
    """Analyze email content for phishing indicators"""
    try:
        # Check if sender is blacklisted
        if request.sender:
            blacklist_entry = await security_manager.check_blacklist(request.sender, "email")
            if blacklist_entry:
                result = EmailAnalysisResult(
                    sender=request.sender,
                    subject=request.subject,
                    is_phishing=True,
                    confidence_score=0.95,
                    risk_level="critical",
                    analysis_details={"blacklisted": True, "reason": blacklist_entry.reason},
                    nlp_analysis={"classification": "blacklisted"},
                    processing_time=0.01,
                    user_id=request.user_id
                )
                await db.email_results.insert_one(result.dict())
                return result
        
        # Perform analysis
        result = await analyzer.analyze_email_content(
            request.sender, request.subject, request.content, request.user_id
        )
        
        # Store result
        await db.email_results.insert_one(result.dict())
        
        # Execute automated response actions
        background_tasks.add_task(security_manager.execute_response_actions, result)
        
        # Create alert if high risk
        if result.risk_level in ['high', 'critical']:
            alert = AlertEntry(
                email_sender=request.sender,
                alert_type="email_threat",
                risk_level=result.risk_level,
                message=f"High-risk phishing email detected from {request.sender}",
                user_id=request.user_id
            )
            await db.alerts.insert_one(alert.dict())
        
        return result
        
    except Exception as e:
        logging.error(f"Email analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Email analysis failed: {str(e)}")

# Email file upload analysis
@api_router.post("/email/upload-analyze")
async def analyze_email_file(file: UploadFile = File(...), user_id: str = Form(None)):
    """Analyze uploaded email file"""
    try:
        content = await file.read()
        
        # Parse email
        msg = BytesParser(policy=policy.default).parsebytes(content)
        
        sender = msg.get('From', '')
        subject = msg.get('Subject', '')
        
        # Extract body content
        body_content = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body_content += part.get_content()
        else:
            body_content = msg.get_content()
        
        # Analyze
        request = EmailAnalysisRequest(
            sender=sender,
            subject=subject,
            content=body_content,
            user_id=user_id
        )
        
        return await analyze_email(request, BackgroundTasks())
        
    except Exception as e:
        logging.error(f"Email file analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Email file analysis failed: {str(e)}")

# Blacklist Management
@api_router.post("/blacklist", response_model=BlacklistEntry)
async def add_blacklist_entry(entry: BlacklistEntry):
    """Add entry to blacklist"""
    existing = await security_manager.check_blacklist(entry.value, entry.entry_type)
    if existing:
        raise HTTPException(status_code=409, detail="Entry already exists in blacklist")
    
    await db.blacklist.insert_one(entry.dict())
    return entry

@api_router.get("/blacklist", response_model=List[BlacklistEntry])
async def get_blacklist(limit: int = 100, entry_type: Optional[str] = None):
    """Get blacklist entries"""
    query = {"is_active": True}
    if entry_type:
        query["entry_type"] = entry_type
    
    entries = await db.blacklist.find(query).sort("timestamp", -1).limit(limit).to_list(limit)
    return [BlacklistEntry(**entry) for entry in entries]

@api_router.delete("/blacklist/{entry_id}")
async def remove_blacklist_entry(entry_id: str):
    """Remove entry from blacklist"""
    result = await db.blacklist.update_one(
        {"id": entry_id}, 
        {"$set": {"is_active": False}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Entry not found")
    return {"message": "Entry removed from blacklist"}

# Security Incidents
@api_router.get("/incidents", response_model=List[SecurityIncident])
async def get_incidents(limit: int = 50, status: Optional[str] = None):
    """Get security incidents"""
    query = {}
    if status:
        query["status"] = status
    
    incidents = await db.incidents.find(query).sort("timestamp", -1).limit(limit).to_list(limit)
    return [SecurityIncident(**incident) for incident in incidents]

@api_router.put("/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, status: str, assigned_to: Optional[str] = None):
    """Update incident status"""
    update_data = {"status": status}
    if assigned_to:
        update_data["assigned_to"] = assigned_to
    if status == "resolved":
        update_data["resolved_at"] = datetime.now(timezone.utc)
    
    result = await db.incidents.update_one({"id": incident_id}, {"$set": update_data})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"message": "Incident updated successfully"}

# Quarantine Management
@api_router.get("/quarantine", response_model=List[QuarantinedItem])
async def get_quarantine(limit: int = 50):
    """Get quarantined items"""
    items = await db.quarantine.find().sort("timestamp", -1).limit(limit).to_list(limit)
    return [QuarantinedItem(**item) for item in items]

@api_router.put("/quarantine/{item_id}/release")
async def release_quarantined_item(item_id: str):
    """Release item from quarantine"""
    result = await db.quarantine.update_one(
        {"id": item_id}, 
        {"$set": {"release_date": datetime.now(timezone.utc)}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item released from quarantine"}

# Admin Settings
@api_router.post("/admin/settings", response_model=AdminSettings)
async def update_admin_settings(settings: AdminSettings):
    """Update admin settings"""
    await db.admin_settings.replace_one({}, settings.dict(), upsert=True)
    return settings

@api_router.get("/admin/settings", response_model=AdminSettings)
async def get_admin_settings():
    """Get admin settings"""
    settings = await db.admin_settings.find_one()
    if not settings:
        # Return default settings
        default_settings = AdminSettings(updated_by="system")
        await db.admin_settings.insert_one(default_settings.dict())
        return default_settings
    return AdminSettings(**settings)

# Existing endpoints (updated)
@api_router.get("/results", response_model=List[PhishingResult])
async def get_analysis_results(limit: int = 50, user_id: Optional[str] = None):
    """Get analysis results history"""
    query = {}
    if user_id:
        query['user_id'] = user_id
    
    results = await db.phishing_results.find(query).sort("timestamp", -1).limit(limit).to_list(limit)
    return [PhishingResult(**result) for result in results]

@api_router.get("/email/results", response_model=List[EmailAnalysisResult])
async def get_email_results(limit: int = 50, user_id: Optional[str] = None):
    """Get email analysis results"""
    query = {}
    if user_id:
        query['user_id'] = user_id
    
    results = await db.email_results.find(query).sort("timestamp", -1).limit(limit).to_list(limit)
    return [EmailAnalysisResult(**result) for result in results]

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
    """Get comprehensive statistics"""
    query = {}
    if user_id:
        query['user_id'] = user_id
    
    # URL analysis stats
    total_url_analyses = await db.phishing_results.count_documents(query)
    url_phishing_detected = await db.phishing_results.count_documents({**query, "is_phishing": True})
    
    # Email analysis stats
    total_email_analyses = await db.email_results.count_documents(query)
    email_phishing_detected = await db.email_results.count_documents({**query, "is_phishing": True})
    
    # Combined stats
    total_analyses = total_url_analyses + total_email_analyses
    total_phishing = url_phishing_detected + email_phishing_detected
    
    # Risk level distribution
    url_risk_levels = await db.phishing_results.aggregate([
        {"$match": query},
        {"$group": {"_id": "$risk_level", "count": {"$sum": 1}}}
    ]).to_list(None)
    
    email_risk_levels = await db.email_results.aggregate([
        {"$match": query},
        {"$group": {"_id": "$risk_level", "count": {"$sum": 1}}}
    ]).to_list(None)
    
    # Combine risk distributions
    risk_distribution = {}
    for item in url_risk_levels + email_risk_levels:
        risk_level = item['_id']
        count = item['count']
        risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + count
    
    # Recent activity (last 7 days)
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    recent_url_analyses = await db.phishing_results.count_documents({
        **query, 
        "timestamp": {"$gte": week_ago}
    })
    recent_email_analyses = await db.email_results.count_documents({
        **query, 
        "timestamp": {"$gte": week_ago}
    })
    
    # Security stats
    total_incidents = await db.incidents.count_documents()
    open_incidents = await db.incidents.count_documents({"status": "open"})
    quarantined_items = await db.quarantine.count_documents()
    blacklist_entries = await db.blacklist.count_documents({"is_active": True})
    
    return {
        'total_analyses': total_analyses,
        'url_analyses': total_url_analyses,
        'email_analyses': total_email_analyses,
        'phishing_detected': total_phishing,
        'detection_rate': total_phishing / total_analyses if total_analyses > 0 else 0,
        'risk_distribution': risk_distribution,
        'recent_activity': recent_url_analyses + recent_email_analyses,
        'security_stats': {
            'total_incidents': total_incidents,
            'open_incidents': open_incidents,
            'quarantined_items': quarantined_items,
            'blacklist_entries': blacklist_entries
        }
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