import React, { useState, useEffect } from "react";
import "./App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import axios from "axios";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./components/ui/card";
import { Button } from "./components/ui/button";
import { Input } from "./components/ui/input";
import { Alert, AlertDescription } from "./components/ui/alert";
import { Badge } from "./components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs";
import { Progress } from "./components/ui/progress";
import { Textarea } from "./components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./components/ui/select";
import { Switch } from "./components/ui/switch";
import { Label } from "./components/ui/label";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "./components/ui/dialog";
import { 
  AlertTriangle, Shield, Activity, BarChart3, Zap, Globe, Clock, CheckCircle, 
  Mail, FileText, Settings, Ban, Archive, Users, Eye, Trash2, Upload,
  ShieldCheck, AlertCircle, ShieldAlert, Database, Bell, MessageSquare,
  XCircle, CheckCircle2, Pause, Play
} from "lucide-react";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const Dashboard = () => {
  const [activeTab, setActiveTab] = useState("url-analysis");
  
  // URL Analysis State
  const [url, setUrl] = useState("");
  const [urlAnalyzing, setUrlAnalyzing] = useState(false);
  const [urlResult, setUrlResult] = useState(null);
  
  // Email Analysis State
  const [emailSender, setEmailSender] = useState("");
  const [emailSubject, setEmailSubject] = useState("");
  const [emailContent, setEmailContent] = useState("");
  const [emailAnalyzing, setEmailAnalyzing] = useState(false);
  const [emailResult, setEmailResult] = useState(null);
  const [emailFile, setEmailFile] = useState(null);
  
  // Data State
  const [urlResults, setUrlResults] = useState([]);
  const [emailResults, setEmailResults] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [blacklist, setBlacklist] = useState([]);
  const [quarantine, setQuarantine] = useState([]);
  const [stats, setStats] = useState({});
  const [adminSettings, setAdminSettings] = useState({});
  
  // UI State
  const [loading, setLoading] = useState(true);
  const [showAddBlacklistDialog, setShowAddBlacklistDialog] = useState(false);
  const [newBlacklistEntry, setNewBlacklistEntry] = useState({
    entry_type: "url",
    value: "",
    reason: "",
    severity: "medium",
    added_by: "admin"
  });

  // Fetch initial data
  useEffect(() => {
    fetchAllData();
  }, []);

  const fetchAllData = async () => {
    try {
      await Promise.all([
        fetchUrlResults(),
        fetchEmailResults(),
        fetchAlerts(),
        fetchIncidents(),
        fetchBlacklist(),
        fetchQuarantine(),
        fetchStats(),
        fetchAdminSettings()
      ]);
    } catch (error) {
      console.error("Error fetching data:", error);
    } finally {
      setLoading(false);
    }
  };

  const fetchUrlResults = async () => {
    try {
      const response = await axios.get(`${API}/results?limit=10`);
      setUrlResults(response.data);
    } catch (error) {
      console.error("Error fetching URL results:", error);
    }
  };

  const fetchEmailResults = async () => {
    try {
      const response = await axios.get(`${API}/email/results?limit=10`);
      setEmailResults(response.data);
    } catch (error) {
      console.error("Error fetching email results:", error);
    }
  };

  const fetchAlerts = async () => {
    try {
      const response = await axios.get(`${API}/alerts?limit=10`);
      setAlerts(response.data);
    } catch (error) {
      console.error("Error fetching alerts:", error);
    }
  };

  const fetchIncidents = async () => {
    try {
      const response = await axios.get(`${API}/incidents?limit=10`);
      setIncidents(response.data);
    } catch (error) {
      console.error("Error fetching incidents:", error);
    }
  };

  const fetchBlacklist = async () => {
    try {
      const response = await axios.get(`${API}/blacklist?limit=20`);
      setBlacklist(response.data);
    } catch (error) {
      console.error("Error fetching blacklist:", error);
    }
  };

  const fetchQuarantine = async () => {
    try {
      const response = await axios.get(`${API}/quarantine?limit=20`);
      setQuarantine(response.data);
    } catch (error) {
      console.error("Error fetching quarantine:", error);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API}/stats`);
      setStats(response.data);
    } catch (error) {
      console.error("Error fetching stats:", error);
    }
  };

  const fetchAdminSettings = async () => {
    try {
      const response = await axios.get(`${API}/admin/settings`);
      setAdminSettings(response.data);
    } catch (error) {
      console.error("Error fetching admin settings:", error);
    }
  };

  // URL Analysis
  const analyzeUrl = async () => {
    if (!url.trim()) return;
    
    setUrlAnalyzing(true);
    setUrlResult(null);
    
    try {
      const response = await axios.post(`${API}/analyze`, {
        url: url.trim(),
        user_id: "default_user"
      });
      
      setUrlResult(response.data);
      await fetchAllData();
    } catch (error) {
      console.error("Error analyzing URL:", error);
      setUrlResult({
        error: true,
        message: error.response?.data?.detail || "فشل في تحليل الرابط. يرجى المحاولة مرة أخرى."
      });
    } finally {
      setUrlAnalyzing(false);
    }
  };

  // Email Analysis
  const analyzeEmail = async () => {
    if (!emailContent.trim()) return;
    
    setEmailAnalyzing(true);
    setEmailResult(null);
    
    try {
      const response = await axios.post(`${API}/email/analyze`, {
        sender: emailSender,
        subject: emailSubject,
        content: emailContent,
        user_id: "default_user"
      });
      
      setEmailResult(response.data);
      await fetchAllData();
    } catch (error) {
      console.error("Error analyzing email:", error);
      setEmailResult({
        error: true,
        message: error.response?.data?.detail || "فشل في تحليل الإيميل. يرجى المحاولة مرة أخرى."
      });
    } finally {
      setEmailAnalyzing(false);
    }
  };

  // Email File Upload
  const analyzeEmailFile = async () => {
    if (!emailFile) return;
    
    setEmailAnalyzing(true);
    setEmailResult(null);
    
    const formData = new FormData();
    formData.append('file', emailFile);
    formData.append('user_id', 'default_user');
    
    try {
      const response = await axios.post(`${API}/email/upload-analyze`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      setEmailResult(response.data);
      await fetchAllData();
    } catch (error) {
      console.error("Error analyzing email file:", error);
      setEmailResult({
        error: true,
        message: error.response?.data?.detail || "فشل في تحليل ملف الإيميل. يرجى المحاولة مرة أخرى."
      });
    } finally {
      setEmailAnalyzing(false);
    }
  };

  // Blacklist Management
  const addToBlacklist = async () => {
    try {
      await axios.post(`${API}/blacklist`, newBlacklistEntry);
      setShowAddBlacklistDialog(false);
      setNewBlacklistEntry({
        entry_type: "url",
        value: "",
        reason: "",
        severity: "medium",
        added_by: "admin"
      });
      await fetchBlacklist();
    } catch (error) {
      console.error("Error adding to blacklist:", error);
    }
  };

  const removeFromBlacklist = async (entryId) => {
    try {
      await axios.delete(`${API}/blacklist/${entryId}`);
      await fetchBlacklist();
    } catch (error) {
      console.error("Error removing from blacklist:", error);
    }
  };

  // Incident Management
  const updateIncidentStatus = async (incidentId, status) => {
    try {
      await axios.put(`${API}/incidents/${incidentId}/status`, { status });
      await fetchIncidents();
    } catch (error) {
      console.error("Error updating incident:", error);
    }
  };

  // Quarantine Management
  const releaseFromQuarantine = async (itemId) => {
    try {
      await axios.put(`${API}/quarantine/${itemId}/release`);
      await fetchQuarantine();
    } catch (error) {
      console.error("Error releasing from quarantine:", error);
    }
  };

  // Utility functions
  const getRiskColor = (riskLevel) => {
    switch (riskLevel) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const getRiskBadgeColor = (riskLevel) => {
    switch (riskLevel) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'default';
      case 'low': return 'secondary';
      default: return 'outline';
    }
  };

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleString('ar-SA');
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'open': return <AlertCircle className="h-4 w-4 text-red-500" />;
      case 'investigating': return <Eye className="h-4 w-4 text-yellow-500" />;
      case 'resolved': return <CheckCircle2 className="h-4 w-4 text-green-500" />;
      case 'closed': return <XCircle className="h-4 w-4 text-gray-500" />;
      default: return <AlertCircle className="h-4 w-4 text-gray-500" />;
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-lg text-gray-600">جاري تحميل النظام...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100">
      <div className="container mx-auto p-6">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 bg-blue-600 rounded-2xl">
              <Shield className="h-8 w-8 text-white" />
            </div>
            <div>
              <h1 className="text-4xl font-bold text-gray-900">نظام كشف التصيد الإلكتروني المتقدم</h1>
              <p className="text-lg text-gray-600 mt-1">حماية شاملة ضد الهجمات السيبرانية مع إجراءات وقائية تلقائية</p>
            </div>
          </div>
        </div>

        {/* Main Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-6 bg-white/70 backdrop-blur-sm">
            <TabsTrigger value="url-analysis" className="flex items-center gap-2">
              <Globe className="h-4 w-4" />
              تحليل الروابط
            </TabsTrigger>
            <TabsTrigger value="email-analysis" className="flex items-center gap-2">
              <Mail className="h-4 w-4" />
              تحليل الإيميل
            </TabsTrigger>
            <TabsTrigger value="security-dashboard" className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4" />
              لوحة الأمان
            </TabsTrigger>
            <TabsTrigger value="incidents" className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              الحوادث الأمنية
            </TabsTrigger>
            <TabsTrigger value="management" className="flex items-center gap-2">
              <Database className="h-4 w-4" />
              إدارة النظام
            </TabsTrigger>
            <TabsTrigger value="settings" className="flex items-center gap-2">
              <Settings className="h-4 w-4" />
              الإعدادات
            </TabsTrigger>
          </TabsList>

          {/* URL Analysis Tab */}
          <TabsContent value="url-analysis">
            <div className="space-y-6">
              {/* URL Analysis Card */}
              <Card className="border-0 shadow-2xl bg-white/70 backdrop-blur-sm">
                <CardHeader className="pb-4">
                  <CardTitle className="flex items-center gap-2 text-xl">
                    <Globe className="h-6 w-6 text-blue-600" />
                    تحليل الروابط المتقدم
                  </CardTitle>
                  <CardDescription>
                    أدخل الرابط المشكوك فيه للحصول على تحليل شامل مع إجراءات وقائية تلقائية
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex gap-3">
                    <Input
                      type="url"
                      placeholder="https://example.com"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      className="flex-1 h-12 text-lg border-2 focus:border-blue-500"
                      dir="ltr"
                    />
                    <Button 
                      onClick={analyzeUrl} 
                      disabled={urlAnalyzing || !url.trim()}
                      className="h-12 px-8 bg-blue-600 hover:bg-blue-700 text-white font-medium"
                    >
                      {urlAnalyzing ? (
                        <div className="flex items-center gap-2">
                          <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                          جاري التحليل...
                        </div>
                      ) : (
                        <div className="flex items-center gap-2">
                          <Zap className="h-4 w-4" />
                          تحليل متقدم
                        </div>
                      )}
                    </Button>
                  </div>

                  {/* URL Analysis Result */}
                  {urlResult && !urlResult.error && (
                    <div className="mt-6 p-6 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-2xl border border-blue-200">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-3">
                          {urlResult.is_phishing ? (
                            <AlertTriangle className="h-8 w-8 text-red-500" />
                          ) : (
                            <CheckCircle className="h-8 w-8 text-green-500" />
                          )}
                          <div>
                            <h3 className="text-2xl font-bold text-gray-900">
                              {urlResult.is_phishing ? "تم اكتشاف تهديد!" : "الرابط آمن"}
                            </h3>
                            <p className="text-gray-600">
                              مستوى الثقة: {(urlResult.confidence_score * 100).toFixed(1)}%
                            </p>
                          </div>
                        </div>
                        <Badge variant={getRiskBadgeColor(urlResult.risk_level)} className="text-lg px-4 py-2">
                          {urlResult.risk_level === 'critical' && 'حرج'}
                          {urlResult.risk_level === 'high' && 'عالي'}
                          {urlResult.risk_level === 'medium' && 'متوسط'}
                          {urlResult.risk_level === 'low' && 'منخفض'}
                        </Badge>
                      </div>

                      <div className="mb-4">
                        <div className="flex justify-between text-sm mb-2">
                          <span>مستوى الخطورة</span>
                          <span>{(urlResult.confidence_score * 100).toFixed(1)}%</span>
                        </div>
                        <Progress value={urlResult.confidence_score * 100} className="h-3" />
                      </div>

                      {/* Analysis Details */}
                      <div className="grid md:grid-cols-2 gap-4 mt-6">
                        <div className="bg-white/60 p-4 rounded-xl">
                          <h4 className="font-semibold mb-2 flex items-center gap-2">
                            <BarChart3 className="h-4 w-4" />
                            العوامل المؤثرة
                          </h4>
                          <ul className="text-sm text-gray-600 space-y-1">
                            {urlResult.ml_prediction.contributing_factors.map((factor, idx) => (
                              <li key={idx} className="flex items-center gap-2">
                                <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                                {factor}
                              </li>
                            ))}
                          </ul>
                        </div>

                        <div className="bg-white/60 p-4 rounded-xl">
                          <h4 className="font-semibold mb-2 flex items-center gap-2">
                            <Clock className="h-4 w-4" />
                            تفاصيل التحليل
                          </h4>
                          <div className="text-sm text-gray-600 space-y-1">
                            <p>وقت المعالجة: {urlResult.processing_time.toFixed(2)} ثانية</p>
                            <p>حالة الاستجابة: {urlResult.analysis_details.sandbox_analysis.status_code}</p>
                            <p>عدد التحويلات: {urlResult.analysis_details.sandbox_analysis.redirect_count}</p>
                          </div>
                        </div>
                      </div>

                      {/* Preventive Actions Taken */}
                      {urlResult.risk_level === 'high' || urlResult.risk_level === 'critical' ? (
                        <div className="mt-6 p-4 bg-red-50 border border-red-200 rounded-xl">
                          <h4 className="font-semibold text-red-800 mb-2 flex items-center gap-2">
                            <ShieldAlert className="h-4 w-4" />
                            الإجراءات الوقائية المتخذة
                          </h4>
                          <ul className="text-sm text-red-700 space-y-1">
                            <li>• تم إضافة الرابط إلى القائمة السوداء تلقائياً</li>
                            <li>• تم إنشاء تنبيه أمني للمسؤولين</li>
                            <li>• تم توثيق الحادثة في سجل الأمان</li>
                            <li>• تم حجر الرابط لمنع الوصول إليه</li>
                          </ul>
                        </div>
                      ) : null}
                    </div>
                  )}

                  {urlResult && urlResult.error && (
                    <Alert className="border-red-200 bg-red-50">
                      <AlertTriangle className="h-4 w-4 text-red-600" />
                      <AlertDescription className="text-red-700">
                        {urlResult.message}
                      </AlertDescription>
                    </Alert>
                  )}
                </CardContent>
              </Card>

              {/* Recent URL Analysis Results */}
              <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>آخر تحليلات الروابط</CardTitle>
                  <CardDescription>سجل مفصل لجميع عمليات تحليل الروابط المنجزة</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {urlResults.map((item, idx) => (
                      <div key={idx} className="flex items-center justify-between p-4 bg-white/60 rounded-xl border border-gray-200">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <div className={`w-3 h-3 rounded-full ${getRiskColor(item.risk_level)}`}></div>
                            <span className="font-mono text-sm text-gray-600 break-all">
                              {item.url.length > 50 ? `${item.url.substring(0, 50)}...` : item.url}
                            </span>
                          </div>
                          <div className="flex items-center gap-4 text-sm text-gray-500">
                            <span>{formatTime(item.timestamp)}</span>
                            <span>الثقة: {(item.confidence_score * 100).toFixed(1)}%</span>
                            <span>المعالجة: {item.processing_time.toFixed(2)}ث</span>
                          </div>
                        </div>
                        <Badge variant={getRiskBadgeColor(item.risk_level)}>
                          {item.risk_level === 'critical' && 'حرج'}
                          {item.risk_level === 'high' && 'عالي'}
                          {item.risk_level === 'medium' && 'متوسط'}
                          {item.risk_level === 'low' && 'منخفض'}
                        </Badge>
                      </div>
                    ))}
                    {urlResults.length === 0 && (
                      <div className="text-center py-8 text-gray-500">
                        لا توجد نتائج بعد. ابدأ بتحليل أول رابط!
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Email Analysis Tab */}
          <TabsContent value="email-analysis">
            <div className="space-y-6">
              {/* Email Analysis Card */}
              <Card className="border-0 shadow-2xl bg-white/70 backdrop-blur-sm">
                <CardHeader className="pb-4">
                  <CardTitle className="flex items-center gap-2 text-xl">
                    <Mail className="h-6 w-6 text-blue-600" />
                    تحليل رسائل الإيميل المتقدم
                  </CardTitle>
                  <CardDescription>
                    تحليل شامل لرسائل الإيميل للكشف عن التصيد والمحتوى المشبوه
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <Tabs defaultValue="manual-input" className="space-y-4">
                    <TabsList className="grid w-full grid-cols-2">
                      <TabsTrigger value="manual-input">إدخال يدوي</TabsTrigger>
                      <TabsTrigger value="file-upload">رفع ملف إيميل</TabsTrigger>
                    </TabsList>
                    
                    <TabsContent value="manual-input" className="space-y-4">
                      <div className="grid md:grid-cols-2 gap-4">
                        <div>
                          <Label htmlFor="email-sender">عنوان المرسل</Label>
                          <Input
                            id="email-sender"
                            type="email"
                            placeholder="example@domain.com"
                            value={emailSender}
                            onChange={(e) => setEmailSender(e.target.value)}
                            className="mt-1"
                            dir="ltr"
                          />
                        </div>
                        <div>
                          <Label htmlFor="email-subject">موضوع الرسالة</Label>
                          <Input
                            id="email-subject"
                            placeholder="موضوع الإيميل"
                            value={emailSubject}
                            onChange={(e) => setEmailSubject(e.target.value)}
                            className="mt-1"
                          />
                        </div>
                      </div>
                      
                      <div>
                        <Label htmlFor="email-content">محتوى الرسالة</Label>
                        <Textarea
                          id="email-content"
                          placeholder="ألصق محتوى الإيميل هنا..."
                          value={emailContent}
                          onChange={(e) => setEmailContent(e.target.value)}
                          className="mt-1 min-h-32"
                        />
                      </div>
                      
                      <Button 
                        onClick={analyzeEmail} 
                        disabled={emailAnalyzing || !emailContent.trim()}
                        className="w-full h-12 bg-blue-600 hover:bg-blue-700 text-white font-medium"
                      >
                        {emailAnalyzing ? (
                          <div className="flex items-center gap-2">
                            <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                            جاري تحليل الإيميل...
                          </div>
                        ) : (
                          <div className="flex items-center gap-2">
                            <Mail className="h-4 w-4" />
                            تحليل الإيميل
                          </div>
                        )}
                      </Button>
                    </TabsContent>
                    
                    <TabsContent value="file-upload" className="space-y-4">
                      <div>
                        <Label htmlFor="email-file">ملف الإيميل (.eml, .msg)</Label>
                        <Input
                          id="email-file"
                          type="file"
                          accept=".eml,.msg,.txt"
                          onChange={(e) => setEmailFile(e.target.files[0])}
                          className="mt-1"
                        />
                      </div>
                      
                      <Button 
                        onClick={analyzeEmailFile} 
                        disabled={emailAnalyzing || !emailFile}
                        className="w-full h-12 bg-blue-600 hover:bg-blue-700 text-white font-medium"
                      >
                        {emailAnalyzing ? (
                          <div className="flex items-center gap-2">
                            <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                            جاري تحليل الملف...
                          </div>
                        ) : (
                          <div className="flex items-center gap-2">
                            <Upload className="h-4 w-4" />
                            تحليل ملف الإيميل
                          </div>
                        )}
                      </Button>
                    </TabsContent>
                  </Tabs>

                  {/* Email Analysis Result */}
                  {emailResult && !emailResult.error && (
                    <div className="mt-6 p-6 bg-gradient-to-r from-green-50 to-blue-50 rounded-2xl border border-green-200">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-3">
                          {emailResult.is_phishing ? (
                            <AlertTriangle className="h-8 w-8 text-red-500" />
                          ) : (
                            <CheckCircle className="h-8 w-8 text-green-500" />
                          )}
                          <div>
                            <h3 className="text-2xl font-bold text-gray-900">
                              {emailResult.is_phishing ? "إيميل مشبوه!" : "الإيميل آمن"}
                            </h3>
                            <p className="text-gray-600">
                              مستوى الثقة: {(emailResult.confidence_score * 100).toFixed(1)}%
                            </p>
                          </div>
                        </div>
                        <Badge variant={getRiskBadgeColor(emailResult.risk_level)} className="text-lg px-4 py-2">
                          {emailResult.risk_level === 'critical' && 'حرج'}
                          {emailResult.risk_level === 'high' && 'عالي'}
                          {emailResult.risk_level === 'medium' && 'متوسط'}
                          {emailResult.risk_level === 'low' && 'منخفض'}
                        </Badge>
                      </div>

                      <div className="mb-4">
                        <div className="flex justify-between text-sm mb-2">
                          <span>مستوى الخطورة</span>
                          <span>{(emailResult.confidence_score * 100).toFixed(1)}%</span>
                        </div>
                        <Progress value={emailResult.confidence_score * 100} className="h-3" />
                      </div>

                      {/* Email Analysis Details */}
                      <div className="grid md:grid-cols-3 gap-4 mt-6">
                        <div className="bg-white/60 p-4 rounded-xl">
                          <h4 className="font-semibold mb-2 flex items-center gap-2">
                            <MessageSquare className="h-4 w-4" />
                            تفاصيل الإيميل
                          </h4>
                          <div className="text-sm text-gray-600 space-y-1">
                            <p>المرسل: {emailResult.sender || 'غير محدد'}</p>
                            <p>الموضوع: {emailResult.subject || 'بدون موضوع'}</p>
                            <p>الروابط المكتشفة: {emailResult.urls_found.length}</p>
                          </div>
                        </div>

                        <div className="bg-white/60 p-4 rounded-xl">
                          <h4 className="font-semibold mb-2 flex items-center gap-2">
                            <BarChart3 className="h-4 w-4" />
                            العوامل المؤثرة
                          </h4>
                          <ul className="text-sm text-gray-600 space-y-1">
                            {emailResult.analysis_details.risk_factors.map((factor, idx) => (
                              <li key={idx} className="flex items-center gap-2">
                                <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                                {factor}
                              </li>
                            ))}
                          </ul>
                        </div>

                        <div className="bg-white/60 p-4 rounded-xl">
                          <h4 className="font-semibold mb-2 flex items-center gap-2">
                            <Clock className="h-4 w-4" />
                            تفاصيل التحليل
                          </h4>
                          <div className="text-sm text-gray-600 space-y-1">
                            <p>وقت المعالجة: {emailResult.processing_time.toFixed(2)} ثانية</p>
                            <p>طول المحتوى: {emailResult.analysis_details.content_length} حرف</p>
                            <p>سمعة المرسل: {(emailResult.sender_reputation.score * 100).toFixed(0)}%</p>
                          </div>
                        </div>
                      </div>

                      {/* URLs Found */}
                      {emailResult.urls_found.length > 0 && (
                        <div className="mt-6 p-4 bg-yellow-50 border border-yellow-200 rounded-xl">
                          <h4 className="font-semibold text-yellow-800 mb-2 flex items-center gap-2">
                            <Globe className="h-4 w-4" />
                            الروابط المكتشفة في الإيميل
                          </h4>
                          <ul className="text-sm text-yellow-700 space-y-1">
                            {emailResult.urls_found.map((url, idx) => (
                              <li key={idx} className="font-mono break-all">• {url}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Preventive Actions for Email */}
                      {emailResult.risk_level === 'high' || emailResult.risk_level === 'critical' ? (
                        <div className="mt-6 p-4 bg-red-50 border border-red-200 rounded-xl">
                          <h4 className="font-semibold text-red-800 mb-2 flex items-center gap-2">
                            <ShieldAlert className="h-4 w-4" />
                            الإجراءات الوقائية المتخذة
                          </h4>
                          <ul className="text-sm text-red-700 space-y-1">
                            <li>• تم إضافة المرسل إلى القائمة السوداء</li>
                            <li>• تم حجر الإيميل في منطقة العزل</li>
                            <li>• تم إنشاء تنبيه أمني للمسؤولين</li>
                            <li>• تم توثيق الحادثة في سجل الأمان</li>
                          </ul>
                        </div>
                      ) : null}
                    </div>
                  )}

                  {emailResult && emailResult.error && (
                    <Alert className="border-red-200 bg-red-50">
                      <AlertTriangle className="h-4 w-4 text-red-600" />
                      <AlertDescription className="text-red-700">
                        {emailResult.message}
                      </AlertDescription>
                    </Alert>
                  )}
                </CardContent>
              </Card>

              {/* Recent Email Analysis Results */}
              <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>آخر تحليلات الإيميل</CardTitle>
                  <CardDescription>سجل مفصل لجميع عمليات تحليل الإيميلات المنجزة</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {emailResults.map((item, idx) => (
                      <div key={idx} className="flex items-center justify-between p-4 bg-white/60 rounded-xl border border-gray-200">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <div className={`w-3 h-3 rounded-full ${getRiskColor(item.risk_level)}`}></div>
                            <span className="font-medium text-gray-800">
                              {item.subject || 'بدون موضوع'}
                            </span>
                          </div>
                          <div className="flex items-center gap-4 text-sm text-gray-500">
                            <span>من: {item.sender || 'غير محدد'}</span>
                            <span>{formatTime(item.timestamp)}</span>
                            <span>الثقة: {(item.confidence_score * 100).toFixed(1)}%</span>
                          </div>
                        </div>
                        <Badge variant={getRiskBadgeColor(item.risk_level)}>
                          {item.risk_level === 'critical' && 'حرج'}
                          {item.risk_level === 'high' && 'عالي'}
                          {item.risk_level === 'medium' && 'متوسط'}
                          {item.risk_level === 'low' && 'منخفض'}
                        </Badge>
                      </div>
                    ))}
                    {emailResults.length === 0 && (
                      <div className="text-center py-8 text-gray-500">
                        لا توجد نتائج بعد. ابدأ بتحليل أول إيميل!
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Security Dashboard Tab */}
          <TabsContent value="security-dashboard">
            <div className="space-y-6">
              {/* Statistics Cards */}
              <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
                <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
                  <CardContent className="p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-600">إجمالي التحليلات</p>
                        <p className="text-3xl font-bold text-gray-900">{stats.total_analyses || 0}</p>
                      </div>
                      <div className="p-3 bg-blue-100 rounded-2xl">
                        <Activity className="h-6 w-6 text-blue-600" />
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
                  <CardContent className="p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-600">التهديدات المكتشفة</p>
                        <p className="text-3xl font-bold text-red-600">{stats.phishing_detected || 0}</p>
                      </div>
                      <div className="p-3 bg-red-100 rounded-2xl">
                        <AlertTriangle className="h-6 w-6 text-red-600" />
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
                  <CardContent className="p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-600">الحوادث المفتوحة</p>
                        <p className="text-3xl font-bold text-orange-600">{stats.security_stats?.open_incidents || 0}</p>
                      </div>
                      <div className="p-3 bg-orange-100 rounded-2xl">
                        <AlertCircle className="h-6 w-6 text-orange-600" />
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
                  <CardContent className="p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-600">العناصر المحجورة</p>
                        <p className="text-3xl font-bold text-purple-600">{stats.security_stats?.quarantined_items || 0}</p>
                      </div>
                      <div className="p-3 bg-purple-100 rounded-2xl">
                        <Archive className="h-6 w-6 text-purple-600" />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Recent Alerts */}
              <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Bell className="h-5 w-5 text-red-500" />
                    التنبيهات الأمنية الحديثة
                  </CardTitle>
                  <CardDescription>تنبيهات فورية للتهديدات عالية الخطورة</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {alerts.map((alert, idx) => (
                      <Alert key={idx} className="border-red-200 bg-red-50">
                        <AlertTriangle className="h-4 w-4 text-red-600" />
                        <AlertDescription>
                          <div className="flex items-center justify-between">
                            <div>
                              <p className="font-medium text-red-800">{alert.message}</p>
                              <p className="text-sm text-red-600 mt-1 font-mono break-all">
                                {alert.url || alert.email_sender}
                              </p>
                            </div>
                            <div className="text-right">
                              <Badge variant="destructive">{alert.risk_level}</Badge>
                              <p className="text-xs text-red-600 mt-1">
                                {formatTime(alert.timestamp)}
                              </p>
                            </div>
                          </div>
                        </AlertDescription>
                      </Alert>
                    ))}
                    {alerts.length === 0 && (
                      <div className="text-center py-8 text-gray-500">
                        لا توجد تنبيهات حالياً. النظام يعمل بشكل طبيعي!
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Incidents Tab */}
          <TabsContent value="incidents">
            <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-orange-500" />
                  إدارة الحوادث الأمنية
                </CardTitle>
                <CardDescription>متابعة وإدارة الحوادث الأمنية المكتشفة</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {incidents.map((incident, idx) => (
                    <div key={idx} className="p-4 bg-white/60 rounded-xl border border-gray-200">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-3">
                          {getStatusIcon(incident.status)}
                          <div>
                            <h4 className="font-semibold text-gray-900">{incident.description}</h4>
                            <p className="text-sm text-gray-600">{incident.source_value}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant={getRiskBadgeColor(incident.severity)}>
                            {incident.severity}
                          </Badge>
                          <Select
                            value={incident.status}
                            onValueChange={(status) => updateIncidentStatus(incident.id, status)}
                          >
                            <SelectTrigger className="w-32">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="open">مفتوح</SelectItem>
                              <SelectItem value="investigating">قيد التحقيق</SelectItem>
                              <SelectItem value="resolved">محلول</SelectItem>
                              <SelectItem value="closed">مغلق</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>
                      <div className="text-sm text-gray-500">
                        <span>تاريخ الإنشاء: {formatTime(incident.timestamp)}</span>
                        {incident.resolved_at && (
                          <span className="mr-4">تاريخ الحل: {formatTime(incident.resolved_at)}</span>
                        )}
                      </div>
                    </div>
                  ))}
                  {incidents.length === 0 && (
                    <div className="text-center py-8 text-gray-500">
                      لا توجد حوادث أمنية حالياً!
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Management Tab */}
          <TabsContent value="management">
            <div className="space-y-6">
              {/* Blacklist Management */}
              <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Ban className="h-5 w-5 text-red-500" />
                      إدارة القائمة السوداء
                    </div>
                    <Dialog open={showAddBlacklistDialog} onOpenChange={setShowAddBlacklistDialog}>
                      <DialogTrigger asChild>
                        <Button className="bg-red-600 hover:bg-red-700">
                          إضافة جديد
                        </Button>
                      </DialogTrigger>
                      <DialogContent className="sm:max-w-md">
                        <DialogHeader>
                          <DialogTitle>إضافة إلى القائمة السوداء</DialogTitle>
                          <DialogDescription>
                            أضف عنصر جديد إلى القائمة السوداء لحظره تلقائياً
                          </DialogDescription>
                        </DialogHeader>
                        <div className="space-y-4">
                          <div>
                            <Label>نوع العنصر</Label>
                            <Select
                              value={newBlacklistEntry.entry_type}
                              onValueChange={(value) => setNewBlacklistEntry({...newBlacklistEntry, entry_type: value})}
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="url">رابط</SelectItem>
                                <SelectItem value="domain">نطاق</SelectItem>
                                <SelectItem value="email">إيميل</SelectItem>
                                <SelectItem value="ip">عنوان IP</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div>
                            <Label>القيمة</Label>
                            <Input
                              value={newBlacklistEntry.value}
                              onChange={(e) => setNewBlacklistEntry({...newBlacklistEntry, value: e.target.value})}
                              placeholder="أدخل الرابط أو الإيميل..."
                            />
                          </div>
                          <div>
                            <Label>السبب</Label>
                            <Input
                              value={newBlacklistEntry.reason}
                              onChange={(e) => setNewBlacklistEntry({...newBlacklistEntry, reason: e.target.value})}
                              placeholder="سبب الإضافة للقائمة السوداء"
                            />
                          </div>
                          <div>
                            <Label>مستوى الخطورة</Label>
                            <Select
                              value={newBlacklistEntry.severity}
                              onValueChange={(value) => setNewBlacklistEntry({...newBlacklistEntry, severity: value})}
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="low">منخفض</SelectItem>
                                <SelectItem value="medium">متوسط</SelectItem>
                                <SelectItem value="high">عالي</SelectItem>
                                <SelectItem value="critical">حرج</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <Button onClick={addToBlacklist} className="w-full bg-red-600 hover:bg-red-700">
                            إضافة إلى القائمة السوداء
                          </Button>
                        </div>
                      </DialogContent>
                    </Dialog>
                  </CardTitle>
                  <CardDescription>العناصر المحظورة في النظام</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {blacklist.map((item, idx) => (
                      <div key={idx} className="flex items-center justify-between p-4 bg-white/60 rounded-xl border border-gray-200">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <Badge variant="outline">{item.entry_type}</Badge>
                            <span className="font-mono text-sm text-gray-800 break-all">
                              {item.value}
                            </span>
                          </div>
                          <div className="text-sm text-gray-500">
                            <span>السبب: {item.reason}</span>
                            <span className="mr-4">تاريخ الإضافة: {formatTime(item.timestamp)}</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant={getRiskBadgeColor(item.severity)}>
                            {item.severity}
                          </Badge>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => removeFromBlacklist(item.id)}
                            className="text-red-600 hover:text-red-700"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    ))}
                    {blacklist.length === 0 && (
                      <div className="text-center py-8 text-gray-500">
                        لا توجد عناصر في القائمة السوداء حالياً
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Quarantine Management */}
              <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Archive className="h-5 w-5 text-purple-500" />
                    إدارة الحجر الصحي
                  </CardTitle>
                  <CardDescription>العناصر المحجورة لمراجعة إضافية</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {quarantine.map((item, idx) => (
                      <div key={idx} className="flex items-center justify-between p-4 bg-white/60 rounded-xl border border-gray-200">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <Badge variant="outline">{item.item_type}</Badge>
                            <span className="font-mono text-sm text-gray-800 break-all">
                              {item.item_value}
                            </span>
                          </div>
                          <div className="text-sm text-gray-500">
                            <span>السبب: {item.reason}</span>
                            <span className="mr-4">تاريخ الحجر: {formatTime(item.timestamp)}</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant={getRiskBadgeColor(item.risk_level)}>
                            {item.risk_level}
                          </Badge>
                          {!item.release_date && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => releaseFromQuarantine(item.id)}
                              className="text-green-600 hover:text-green-700"
                            >
                              إطلاق سراح
                            </Button>
                          )}
                        </div>
                      </div>
                    ))}
                    {quarantine.length === 0 && (
                      <div className="text-center py-8 text-gray-500">
                        لا توجد عناصر محجورة حالياً
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Settings Tab */}
          <TabsContent value="settings">
            <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Settings className="h-5 w-5 text-blue-500" />
                  إعدادات النظام
                </CardTitle>
                <CardDescription>تكوين النظام والإجراءات التلقائية</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold">إعدادات الإشعارات</h3>
                    
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <Label htmlFor="email-notifications">إشعارات الإيميل</Label>
                        <Switch
                          id="email-notifications"
                          checked={adminSettings.email_notifications_enabled}
                          onCheckedChange={(checked) => 
                            setAdminSettings({...adminSettings, email_notifications_enabled: checked})
                          }
                        />
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <Label htmlFor="sms-notifications">إشعارات SMS</Label>
                        <Switch
                          id="sms-notifications"
                          checked={adminSettings.sms_notifications_enabled}
                          onCheckedChange={(checked) => 
                            setAdminSettings({...adminSettings, sms_notifications_enabled: checked})
                          }
                        />
                      </div>
                    </div>

                    <div>
                      <Label htmlFor="notification-email">إيميل الإشعارات</Label>
                      <Input
                        id="notification-email"
                        type="email"
                        value={adminSettings.notification_email || ''}
                        onChange={(e) => 
                          setAdminSettings({...adminSettings, notification_email: e.target.value})
                        }
                        placeholder="admin@company.com"
                        className="mt-1"
                      />
                    </div>
                  </div>

                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold">الإجراءات التلقائية</h3>
                    
                    <div className="flex items-center justify-between">
                      <Label htmlFor="auto-blacklist">إضافة تلقائية للقائمة السوداء</Label>
                      <Switch
                        id="auto-blacklist"
                        checked={adminSettings.auto_blacklist_enabled}
                        onCheckedChange={(checked) => 
                          setAdminSettings({...adminSettings, auto_blacklist_enabled: checked})
                        }
                      />
                    </div>

                    <div>
                      <Label htmlFor="quarantine-threshold">حد الحجر التلقائي</Label>
                      <Select
                        value={adminSettings.auto_quarantine_threshold}
                        onValueChange={(value) => 
                          setAdminSettings({...adminSettings, auto_quarantine_threshold: value})
                        }
                      >
                        <SelectTrigger className="mt-1">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="medium">متوسط</SelectItem>
                          <SelectItem value="high">عالي</SelectItem>
                          <SelectItem value="critical">حرج</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="flex items-center justify-between">
                      <Label htmlFor="auto-incident">إنشاء تلقائي للحوادث</Label>
                      <Switch
                        id="auto-incident"
                        checked={adminSettings.incident_auto_assignment}
                        onCheckedChange={(checked) => 
                          setAdminSettings({...adminSettings, incident_auto_assignment: checked})
                        }
                      />
                    </div>
                  </div>
                </div>

                <div className="pt-4 border-t">
                  <Button 
                    onClick={() => {
                      // Update admin settings
                      axios.post(`${API}/admin/settings`, adminSettings)
                        .then(() => {
                          alert('تم حفظ الإعدادات بنجاح!');
                        })
                        .catch((error) => {
                          console.error('Error saving settings:', error);
                          alert('فشل في حفظ الإعدادات');
                        });
                    }}
                    className="bg-blue-600 hover:bg-blue-700"
                  >
                    حفظ الإعدادات
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Dashboard />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;