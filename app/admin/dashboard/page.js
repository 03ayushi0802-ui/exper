"use client";
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import {
  LayoutDashboard, Users, Calendar, ImageIcon, Settings,
  FileText, ShoppingBag, BookOpen, LogOut, Menu, X,
  TrendingUp, Clock, DollarSign, Eye
} from 'lucide-react';

export default function AdminDashboard() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState(null);
  const [activeSection, setActiveSection] = useState('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    verifyAuth();
  }, []);

  const verifyAuth = async () => {
    try {
      const response = await fetch('/api/admin/verify');
      if (response.ok) {
        const data = await response.json();
        setUser(data.user);
      } else {
        router.push('/admin/login');
      }
    } catch (error) {
      router.push('/admin/login');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    await fetch('/api/admin/logout', { method: 'POST' });
    router.push('/admin/login');
  };

  const menuItems = [
    { id: 'overview', icon: LayoutDashboard, label: 'Overview' },
    { id: 'events', icon: Calendar, label: 'Events' },
    { id: 'services', icon: BookOpen, label: 'Services & Aartis' },
    { id: 'gallery', icon: ImageIcon, label: 'Gallery' },
    { id: 'bookings', icon: FileText, label: 'Bookings' },
    { id: 'users', icon: Users, label: 'Users' },
    { id: 'content', icon: FileText, label: 'Content' },
    { id: 'shop', icon: ShoppingBag, label: 'Shop' },
    { id: 'settings', icon: Settings, label: 'Settings' }
  ];

  const stats = [
    { label: 'Total Bookings', value: '234', icon: FileText, color: 'bg-blue-500', change: '+12%' },
    { label: 'Active Users', value: '1,234', icon: Users, color: 'bg-green-500', change: '+8%' },
    { label: 'Events This Month', value: '12', icon: Calendar, color: 'bg-purple-500', change: '+3' },
    { label: 'Revenue', value: '₹45,678', icon: DollarSign, color: 'bg-amber-500', change: '+15%' }
  ];

  if (loading) {
    return (
      <div className="min-h-screen bg-heritage-cream flex items-center justify-center">
        <div className="text-sandalwood text-xl">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-heritage-cream">
      {/* Top Navigation */}
      <nav className="bg-white border-b border-sandalwood/10 sticky top-0 z-50">
        <div className="px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo & Title */}
            <div className="flex items-center">
              <button
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className="lg:hidden mr-3 text-deep-brown"
              >
                {mobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
              </button>
              <h1 className="text-xl font-light text-deep-brown" style={{ fontFamily: 'Cormorant Garamond, serif' }}>
                KuberJi Admin
              </h1>
            </div>

            {/* User Menu */}
            <div className="flex items-center gap-4">
              <button
                onClick={() => router.push('/')}
                className="flex items-center gap-2 text-deep-brown hover:text-sandalwood transition-colors text-sm"
              >
                <Eye size={18} />
                <span className="hidden sm:inline">View Site</span>
              </button>
              <button
                onClick={handleLogout}
                className="flex items-center gap-2 text-deep-brown hover:text-red-600 transition-colors text-sm"
              >
                <LogOut size={18} />
                <span className="hidden sm:inline">Logout</span>
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="flex">
        {/* Sidebar */}
        <aside className={`
          ${mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'}
          lg:translate-x-0 fixed lg:sticky top-16 left-0 h-[calc(100vh-4rem)]
          w-64 bg-white border-r border-sandalwood/10 transition-transform duration-300 z-40
        `}>
          <nav className="p-4 space-y-2">
            {menuItems.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    setActiveSection(item.id);
                    setMobileMenuOpen(false);
                  }}
                  className={`
                    w-full flex items-center gap-3 px-4 py-3 rounded-sm text-left transition-all duration-200
                    ${activeSection === item.id
                      ? 'bg-sandalwood text-ivory'
                      : 'text-deep-brown hover:bg-sandalwood/10'
                    }
                  `}
                >
                  <Icon size={20} />
                  <span className="font-light">{item.label}</span>
                </button>
              );
            })}
          </nav>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-6 lg:p-8">
          {activeSection === 'overview' && (
            <div className="space-y-8">
              <div>
                <h2 className="text-3xl font-light text-deep-brown mb-2" style={{ fontFamily: 'Cormorant Garamond, serif' }}>
                  Dashboard Overview
                </h2>
                <p className="text-incense">Welcome back, {user?.email}</p>
              </div>

              {/* Stats Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
                {stats.map((stat, idx) => {
                  const Icon = stat.icon;
                  return (
                    <motion.div
                      key={idx}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: idx * 0.05 }}
                      className="bg-white rounded-lg p-6 border border-sandalwood/10 shadow-sm"
                    >
                      <div className="flex items-center justify-between mb-4">
                        <div className={`${stat.color} p-3 rounded-lg`}>
                          <Icon size={24} className="text-white" />
                        </div>
                        <span className="text-green-600 text-sm font-medium">{stat.change}</span>
                      </div>
                      <div className="text-2xl font-light text-deep-brown mb-1">{stat.value}</div>
                      <div className="text-sm text-incense">{stat.label}</div>
                    </motion.div>
                  );
                })}
              </div>

              {/* Quick Actions */}
              <div className="bg-white rounded-lg p-6 border border-sandalwood/10">
                <h3 className="text-xl font-light text-deep-brown mb-4" style={{ fontFamily: 'Cormorant Garamond, serif' }}>
                  Quick Actions
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                  <button
                    onClick={() => setActiveSection('events')}
                    className="p-4 border border-sandalwood/20 rounded-sm hover:bg-sandalwood/5 transition-colors text-left"
                  >
                    <Calendar className="text-sandalwood mb-2" size={24} />
                    <div className="font-medium text-deep-brown">Add New Event</div>
                    <div className="text-sm text-incense">Create festival or ceremony</div>
                  </button>
                  <button
                    onClick={() => setActiveSection('gallery')}
                    className="p-4 border border-sandalwood/20 rounded-sm hover:bg-sandalwood/5 transition-colors text-left"
                  >
                    <ImageIcon className="text-sandalwood mb-2" size={24} />
                    <div className="font-medium text-deep-brown">Upload Images</div>
                    <div className="text-sm text-incense">Add to gallery</div>
                  </button>
                  <button
                    onClick={() => setActiveSection('bookings')}
                    className="p-4 border border-sandalwood/20 rounded-sm hover:bg-sandalwood/5 transition-colors text-left"
                  >
                    <FileText className="text-sandalwood mb-2" size={24} />
                    <div className="font-medium text-deep-brown">View Bookings</div>
                    <div className="text-sm text-incense">Manage reservations</div>
                  </button>
                </div>
              </div>

              {/* Recent Activity */}
              <div className="bg-white rounded-lg p-6 border border-sandalwood/10">
                <h3 className="text-xl font-light text-deep-brown mb-4" style={{ fontFamily: 'Cormorant Garamond, serif' }}>
                  Recent Activity
                </h3>
                <div className="space-y-4">
                  {[
                    { action: 'New booking for Morning Aarti', time: '2 hours ago', icon: BookOpen },
                    { action: 'User registration: ram.sharma@email.com', time: '5 hours ago', icon: Users },
                    { action: 'Event published: Dhanteras Pooja', time: '1 day ago', icon: Calendar }
                  ].map((activity, idx) => {
                    const Icon = activity.icon;
                    return (
                      <div key={idx} className="flex items-center gap-4 p-3 hover:bg-sandalwood/5 rounded-sm transition-colors">
                        <div className="bg-sandalwood/10 p-2 rounded-full">
                          <Icon size={18} className="text-sandalwood" />
                        </div>
                        <div className="flex-1">
                          <div className="text-deep-brown text-sm">{activity.action}</div>
                          <div className="text-incense text-xs">{activity.time}</div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {activeSection !== 'overview' && (
            <div className="bg-white rounded-lg p-8 border border-sandalwood/10 min-h-[600px]">
              <h2 className="text-2xl font-light text-deep-brown mb-6" style={{ fontFamily: 'Cormorant Garamond, serif' }}>
                {menuItems.find(item => item.id === activeSection)?.label}
              </h2>
              <div className="text-center py-12 text-incense">
                <div className="text-6xl mb-4">🚧</div>
                <p className="text-lg mb-2">Content Management Module</p>
                <p className="text-sm">
                  This section allows you to manage {activeSection}.<br />
                  Full CRUD operations will be available here.
                </p>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
