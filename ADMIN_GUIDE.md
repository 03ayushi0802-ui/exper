# KuberJi Mandir - Admin Dashboard Guide

## 🚀 Overview

Your website now has a complete admin dashboard system for managing content, bookings, events, and more!

## 📋 Admin Access

### Login Credentials
- **URL**: `/admin/login`
- **Default Email**: `admin@kuberjitemple.org`
- **Default Password**: `Admin@123`

⚠️ **IMPORTANT**: Change these credentials in production by setting environment variables:
```bash
ADMIN_EMAIL=your-admin@email.com
ADMIN_PASSWORD=your-secure-password
ADMIN_JWT_SECRET=your-secret-key
```

## 🎯 Dashboard Features

### 1. Overview Dashboard
- **Total Statistics**: View bookings, users, events, and revenue
- **Quick Actions**: Fast access to common tasks
- **Recent Activity**: Monitor latest actions
- **Real-time Data**: Stats update automatically

### 2. Content Management Sections

#### Events Management
- Create/Edit/Delete temple events and festivals
- Set dates and descriptions
- Upload event images
- Manage event categories

#### Services & Aartis
- Manage pooja services
- Update pricing and timings
- Edit service descriptions
- Control availability

#### Gallery Management
- Upload temple images
- Organize by categories (Temple, Rituals, People, Nature)
- Edit image titles and descriptions
- Delete unwanted images

#### Bookings Management
- View all aarti bookings
- Filter by date and status
- Export booking data
- Manage booking confirmations

#### Users Management
- View registered users
- Manage user accounts
- Monitor user activity
- Send notifications

#### Content Editor
- Update homepage content
- Edit about page
- Modify footer information
- Manage translations

#### Shop Management
- Add/Edit products
- Manage inventory
- Set pricing
- Process orders

#### Settings
- General site settings
- Email configurations
- Payment gateway settings
- Language preferences

## 🔒 Security Features

- **JWT Authentication**: Secure token-based authentication
- **HTTP-only Cookies**: Protected session management
- **Route Protection**: All admin routes are secured
- **Session Timeout**: 24-hour token expiration

## 🎨 Visual Enhancements

Your website has been enhanced with:

### Homepage Improvements
✅ **Hero Section**
- Decorative corner elements
- Enhanced background gradients
- Subtle Om pattern overlay

✅ **Stats Cards**
- Icon emojis for each stat
- Hover animations (lift and scale)
- Enhanced shadows
- Smooth transitions

✅ **Service Cards**
- Om symbol watermarks
- Decorative corner frames
- Better image gradients
- Improved hover effects

✅ **Gallery Section**
- Decorative lamp divider
- Enhanced borders
- Gradient frame effects on hover
- Better button styling

✅ **Donation Section**
- Background pattern overlay
- Card-based layout
- Decorative dividers
- Enhanced call-to-action

### Performance Optimizations
- Reduced animation durations (0.4-0.6s)
- Optimized viewport triggers
- Smoother scroll animations
- Better mobile performance

## 📱 Mobile Responsive

The admin dashboard is fully responsive:
- Hamburger menu on mobile
- Touch-friendly interface
- Optimized layouts
- Fast performance

## 🔄 Workflow Examples

### Adding a New Event
1. Log in to admin dashboard
2. Click "Events" in sidebar
3. Click "Add New Event"
4. Fill in event details
5. Upload image
6. Set date and time
7. Save and publish

### Managing Gallery
1. Navigate to "Gallery" section
2. Upload images in bulk
3. Select category for each image
4. Add titles (auto-translates to Hindi)
5. Organize and save

### Viewing Bookings
1. Go to "Bookings" section
2. Filter by date range
3. View booking details
4. Export to Excel if needed
5. Update status

## 🌐 Bilingual Support

All admin interfaces support:
- English and Hindi content management
- Automatic translation keys
- Font styling for Hindi text
- Seamless language switching

## 📊 Future Enhancements (Roadmap)

The admin panel framework is ready for:
- Email notifications
- SMS alerts
- Analytics dashboard
- User role management
- Content scheduling
- Backup & restore
- API integration
- Mobile app sync

## 💡 Tips & Best Practices

1. **Regular Backups**: Export data regularly
2. **Image Optimization**: Compress images before upload
3. **Content Preview**: Always preview before publishing
4. **Session Security**: Log out when done
5. **Mobile Testing**: Check changes on mobile
6. **Translation Check**: Verify Hindi translations

## 🆘 Troubleshooting

### Cannot Login
- Verify credentials
- Clear browser cache
- Check console for errors
- Ensure `jose` package is installed

### Dashboard Not Loading
- Check network connection
- Verify API routes are working
- Check browser console
- Restart development server

### Images Not Uploading
- Check file size (max 5MB recommended)
- Verify file format (jpg, png, webp)
- Ensure proper permissions
- Check storage space

## 📞 Support

For issues or questions:
- Check console logs for errors
- Review API responses
- Test in different browsers
- Contact development team

---

**Version**: 1.0.0  
**Last Updated**: November 2024  
**Developed for**: KuberJi Mandir, Pandukeshwar
