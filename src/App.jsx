import { useState, useEffect } from 'react'
import './App.css'

import { BrowserRouter as Router, Routes, Route, useNavigate } from 'react-router-dom'
import SchoolsList from './SchoolsList'
import SchoolFinder from './SchoolFinder'
import Emails from './Emails'
import Team from './Team'
import Account from './Account'



function useIsMobile() {
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 770);
  useEffect(() => {
    const onResize = () => setIsMobile(window.innerWidth <= 770);
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);
  return isMobile;
}

function useIsNarrow() {
  const [isNarrow, setIsNarrow] = useState(window.innerWidth <= 1285);
  useEffect(() => {
    const onResize = () => setIsNarrow(window.innerWidth <= 1285);
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);
  return isNarrow;
}


function Home() {
  const isMobile = useIsMobile()
  const isNarrow = useIsNarrow()
  const navigate = useNavigate()
  const images = [
    "/psa pics/bg1.jpg",
    "/psa pics/bg2.jpg",
    "/psa pics/bg3.jpg",
    "/psa pics/bg4.jpg",
    "/psa pics/bg5.jpg"
  ]
  const [bgIndex, setBgIndex] = useState(0)
  const [menuOpen, setMenuOpen] = useState(false)

  useEffect(() => {
    const interval = setInterval(() => {
      setBgIndex(i => (i + 1) % images.length)
    }, 6000)
    return () => clearInterval(interval)
  }, [images.length])

  const buttons = [
    { label: "Schools List +", path: "/schools" },
    { label: "School Finder +", path: "/finder" },
    { label: "Emails +", path: "/emails" },
    { label: "Team +", path: "/team" },
    { label: "Account +", path: "/account" }
  ]

  return isMobile ? (
    // Mobile Format
    <div style={{ position: "relative", minHeight: "100vh", width: "100vw", overflow: "hidden" }}>
      {/* Slideshow background */}
      {images.map((img, i) => (
        <img
          key={img}
          src={img}
          alt=""
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            width: "100vw",
            height: "100vh",
            objectFit: "cover",
            opacity: i === bgIndex ? 1 : 0,
            transition: "opacity 1s",
            zIndex: 0,
            pointerEvents: "none",
            userSelect: "none"
          }}
        />
      ))}

      {/* Title in Center */}
      <div
        style={{
          position: "fixed",
          left: "50%",
          top: "24vh",
          transform: "translateX(-50%)",
          zIndex: 10,
          fontWeight: 900,
          fontSize: "5vw",
          color: "#fff",
          letterSpacing: 1,
          textShadow: "2px 4px 8px rgba(0,0,0,1)",
          maxWidth: "90vw",
          minWidth: "200px",
          wordBreak: "break-word",
          lineHeight: 1.1,
          textAlign: "center"
        }}
      >
        PLAYERS SPORTS ACADEMY SALES
      </div>

      {/* Header container stays on top */}
      <div className="mobile-header-container" style={{ zIndex: 2, position: "fixed" }}>
        <img 
          src="/PSA_logo.png"
          alt="PSA logo"
          className="logo"
        />
        <div style={{ marginLeft: "auto" }}>
            <button
              className="home-btn"
              style={{
                background: "none",
                border: "none",
                fontSize: 32,
                padding: "8px 16px",
                cursor: "pointer",
                color: "#fff",
                boxShadow: "none"
              }}
              onClick={() => setMenuOpen(open => !open)}
              aria-label="Open menu"
            >
              {/* Hamburger icon */}
              <span style={{ display: "inline-block", verticalAlign: "middle" }}>
                <svg width="32" height="32" viewBox="0 0 32 32">
                  <rect y="7" width="32" height="4" rx="2" fill="white"/>
                  <rect y="14" width="32" height="4" rx="2" fill="white"/>
                  <rect y="21" width="32" height="4" rx="2" fill="white"/>
                </svg>
              </span>
          </button>
        </div>
      </div>

            {/* Dropdown menu rendered outside header-container */}
      {isNarrow && menuOpen && (
        <div
          style={{
            position: "fixed",
            top: 90, // just below the header-container (adjust as needed)
            right: "2vw",
            background: "#c40c0c",
            borderRadius: 12,
            boxShadow: "0 4px 24px rgba(0,0,0,0.18)",
            padding: "12px 0",
            minWidth: 180,
            zIndex: 100
          }}
        >
          {buttons.map(btn => (
            <button
              key={btn.path}
              className="home-btn"
              style={{
                display: "block",
                width: "100%",
                background: "none",
                border: "none",
                color: "#fff",
                textAlign: "left",
                padding: "12px 24px",
                fontSize: 18,
                borderBottom: "1px solid rgba(255,255,255,0.1)",
                borderRadius: 0,
                boxShadow: "none"
              }}
              onClick={() => {
                setMenuOpen(false)
                navigate(btn.path)
              }}
            >
              {btn.label}
            </button>
          ))}
        </div>
      )}

    </div>

  //Webpage Format
  ) : (
    <div style={{ position: "relative", minHeight: "100vh", width: "100vw", overflow: "hidden" }}>
      {/* Slideshow background */}
      {images.map((img, i) => (
        <img
          key={img}
          src={img}
          alt=""
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            width: "100vw",
            height: "100vh",
            objectFit: "cover",
            opacity: i === bgIndex ? 1 : 0,
            transition: "opacity 1s",
            zIndex: 0,
            pointerEvents: "none",
            userSelect: "none"
          }}
        />
      ))}

      {/* Title on Left */}
      <div
        style={{
          position: "fixed",
          top: "24vh",
          left: "10vh",
          zIndex: 10,
          fontWeight: 900,
          fontSize: "5vw",
          color: "#fff",
          letterSpacing: 1,
          textShadow: "2px 4px 8px rgba(0,0,0,1)",
          maxWidth: "40vw",
          minWidth: "200px",
          wordBreak: "break-word",
          lineHeight: 1.1
        }}
      >
        PLAYERS SPORTS ACADEMY SALES
      </div>

      {/* Header container stays on top */}
      <div className="header-container" style={{ zIndex: 2, position: "fixed" }}>
        <img 
          src="/PSA_logo.png"
          alt="PSA logo"
          className="logo"
        />
        {/* Show buttons or hamburger menu */}
        {!isNarrow ? (
          buttons.map(btn => (
            <button
              key={btn.path}
              className="home-btn"
              onClick={() => navigate(btn.path)}
            >
              {btn.label}
            </button>
          ))
        ) : (
          <div style={{ marginLeft: "auto" }}>
            <button
              className="home-btn"
              style={{
                background: "none",
                border: "none",
                fontSize: 32,
                padding: "8px 16px",
                cursor: "pointer",
                color: "#fff",
                boxShadow: "none"
              }}
              onClick={() => setMenuOpen(open => !open)}
              aria-label="Open menu"
            >
              {/* Hamburger icon */}
              <span style={{ display: "inline-block", verticalAlign: "middle" }}>
                <svg width="32" height="32" viewBox="0 0 32 32">
                  <rect y="7" width="32" height="4" rx="2" fill="white"/>
                  <rect y="14" width="32" height="4" rx="2" fill="white"/>
                  <rect y="21" width="32" height="4" rx="2" fill="white"/>
                </svg>
              </span>
            </button>
          </div>
        )}
      </div>

      {/* Dropdown menu rendered outside header-container */}
      {isNarrow && menuOpen && (
        <div
          style={{
            position: "fixed",
            top: 90, // just below the header-container (adjust as needed)
            right: "2vw",
            background: "#c40c0c",
            borderRadius: 12,
            boxShadow: "0 4px 24px rgba(0,0,0,0.18)",
            padding: "12px 0",
            minWidth: 180,
            zIndex: 100
          }}
        >
          {buttons.map(btn => (
            <button
              key={btn.path}
              className="home-btn"
              style={{
                display: "block",
                width: "100%",
                background: "none",
                border: "none",
                color: "#fff",
                textAlign: "left",
                padding: "12px 24px",
                fontSize: 18,
                borderBottom: "1px solid rgba(255,255,255,0.1)",
                borderRadius: 0,
                boxShadow: "none"
              }}
              onClick={() => {
                setMenuOpen(false)
                navigate(btn.path)
              }}
            >
              {btn.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}


function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/schools" element={<SchoolsList />} />
        <Route path="/finder" element={<SchoolFinder />} />
        <Route path="/emails" element={<Emails />} />
        <Route path="/team" element={<Team />} />
        <Route path="/account" element={<Account />} />
      </Routes>
    </Router>
  )
}

export default App
