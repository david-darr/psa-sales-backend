import { useNavigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import SchoolMap from './SchoolMap'


const ALL_KEYWORDS = [
  "elementary school",
  "day care",
  "preschool",
  "kindercare",
  "montessori",
  "church school"
]

const buttons = [
    { label: "Home +", path: "/" },
    { label: "Schools List +", path: "/schools" },
    { label: "Emails +", path: "/emails" },
    { label: "Team +", path: "/team" },
    { label: "Account +", path: "/account" }
  ]

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



export default function SchoolFinder() {
  const isMobile = useIsMobile();
  const isNarrow = useIsNarrow();
  const navigate = useNavigate();
  const [address, setAddress] = useState('');
  const [schools, setSchools] = useState([]);
  const [coords, setCoords] = useState(null);
  const [selectedKeywords, setSelectedKeywords] = useState([...ALL_KEYWORDS]);
  const [selectedRouteSchools, setSelectedRouteSchools] = useState([]);
  const [routeOrder, setRouteOrder] = useState(null);
  const [startAddress, setStartAddress] = useState(""); // NEW
  const images = [
    "/psa pics/bg1.jpg",
    "/psa pics/bg2.jpg",
    "/psa pics/bg3.jpg",
    "/psa pics/bg4.jpg",
    "/psa pics/bg5.jpg"
  ];
  const [bgIndex, setBgIndex] = useState(0);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const interval = setInterval(() => {
      setBgIndex(i => (i + 1) % images.length);
    }, 6000);
    return () => clearInterval(interval);
  }, [images.length]);

  function handleKeywordChange(kw) {
    setSelectedKeywords(selectedKeywords =>
      selectedKeywords.includes(kw)
        ? selectedKeywords.filter(k => k !== kw)
        : [...selectedKeywords, kw]
    );
  }

  async function handleSubmit(e) {
    e.preventDefault();
    const res = await fetch('/api/find-schools', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address, keywords: selectedKeywords })
    });
    const data = await res.json();
    setSchools(data.schools);
    setCoords(data.location);
    setSelectedRouteSchools([]); // Reset selected schools for route
    setRouteOrder(null);         // Reset previous route order
  }

  // Handle school selection for route
  function toggleRouteSchool(place_id) {
    setSelectedRouteSchools(selected =>
      selected.includes(place_id)
        ? selected.filter(id => id !== place_id)
        : [...selected, place_id]
    );
  }

  // Send selected schools and starting address to API for route planning
  async function handleCreateRoute() {
    const schoolsToRoute = schools.filter(s => selectedRouteSchools.includes(s.place_id));
    if (schoolsToRoute.length < 2) {
      alert("Select at least two schools for route planning.");
      return;
    }
    if (!startAddress) {
      alert("Please enter a starting address.");
      return;
    }
    const res = await fetch('/api/route-plan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ schools: schoolsToRoute, start_address: startAddress })
    });
    const data = await res.json();
    setRouteOrder(data.route); // route is an array of place_ids in order
  }

  // MOBILE LAYOUT
  if (isMobile) {
    return (
      <div style={{ minHeight: "100vh", width: "100vw", background: "#f5f5f5", position: "relative" }}>
        <div className="mobile-header-container">
          <img src="/PSA_logo.png" alt="PSA logo" className="logo" />
          <div style={{ marginLeft: "auto" }}>
            <button
              className="home-btn"
              onClick={() => setMenuOpen(open => !open)}
              aria-label="Open menu"
            >
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

        {isNarrow && menuOpen && (
          <div style={{
            position: "absolute",
            top: 80,
            right: "12%",
            background: "#c40c0c",
            borderRadius: 12,
            boxShadow: "0 4px 24px rgba(0,0,0,0.18)",
            padding: "12px 0",
            minWidth: 180,
            maxHeight: "60vh",
            overflowY: "auto",
            zIndex: 300
          }}>
            {buttons.map(btn => (
              <button
                key={btn.path}
                className="home-btn"
                onClick={() => {
                  setMenuOpen(false);
                  navigate(btn.path);
                }}
              >
                {btn.label}
              </button>
            ))}
          </div>
        )}

        <div style={{ width: "100vw", height: 210, overflow: "hidden", marginTop: 70 }}>
          <img
            src={images[bgIndex]}
            alt=""
            style={{ width: "100vw", height: 210, objectFit: "cover", display: "block" }}
          />
        </div>

        <div
          style={{
            position: "absolute",
            left: "50%",
            top: 130,
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
            textAlign: "center",
            pointerEvents: "none"
          }}
        >
          SCHOOL FINDER
        </div>

        <div style={{ margin: "32px auto 0 auto", maxWidth: 500, padding: "0 8px", marginTop: 50, display: "flex", flexDirection: "column", alignItems: "center" }}>
          <form onSubmit={handleSubmit} style={{ textAlign: "center", width: "100%" }}>
            <input
              className="schools-search-bar"
              type="text"
              value={address}
              onChange={e => setAddress(e.target.value)}
              placeholder="Enter address or location"
            />
            <div style={{ margin: "16px 0", display: "flex", flexWrap: "wrap", justifyContent: "center" }}>
              {ALL_KEYWORDS.map(kw => (
                <label key={kw} className="schools-keyword-label">
                  <input
                    type="checkbox"
                    checked={selectedKeywords.includes(kw)}
                    onChange={() => handleKeywordChange(kw)}
                  />
                  {kw}
                </label>
              ))}
            </div>
            <div style={{ display: "flex", justifyContent: "center", marginBottom: 24, width: "100%" }}>
              <button
                type="submit"
                className="home-btn"
                style={{
                  maxWidth: 400,
                  width: "100%",
                  textAlign: "center",
                  display: "flex",
                  justifyContent: "center",
                  alignItems: "center"
                }}
              >
                Find Schools
              </button>
            </div>
          </form>
          <div style={{ width: "100%", display: "flex", flexDirection: "column", alignItems: "center" }}>
            {schools.length > 0 && (
              <div className="schoolfinder-list" style={{ marginTop: 16, width: "100%", maxWidth: 500 }}>
                <h3 style={{ textAlign: "center", color: "#c40c0c" }}>Nearby Schools:</h3>
                <ul style={{ paddingLeft: 0, listStyle: "none" }}>
                  {schools.map(s => (
                    <li key={s.place_id} style={{ marginBottom: 16, textAlign: "center" }}>
                      <label style={{ cursor: "pointer" }}>
                        <input
                          type="checkbox"
                          checked={selectedRouteSchools.includes(s.place_id)}
                          onChange={() => toggleRouteSchool(s.place_id)}
                          style={{ marginRight: 8 }}
                        />
                        <b>{s.name}</b><br />
                        {s.address}
                      </label>
                    </li>
                  ))}
                </ul>
                <div style={{ margin: "16px 0", width: "100%" }}>
                  <input
                    type="text"
                    className="schools-search-bar"
                    value={startAddress}
                    onChange={e => setStartAddress(e.target.value)}
                    placeholder="Enter starting address for route"
                    style={{ width: "100%" }}
                  />
                </div>
                <button
                  className="home-btn"
                  style={{ margin: "16px auto", display: "block" }}
                  onClick={handleCreateRoute}
                  disabled={selectedRouteSchools.length < 2}
                >
                  Create Route
                </button>
                {routeOrder && (
                  <div style={{ marginTop: 16 }}>
                    <h4>Optimal Route Order:</h4>
                    <ol>
                      {routeOrder.map(pid => {
                        const school = schools.find(s => s.place_id === pid);
                        return (
                          <li key={pid}>
                            <b>{school?.name}</b> - {school?.address}
                          </li>
                        );
                      })}
                    </ol>
                  </div>
                )}
              </div>
            )}
            <div style={{ margin: "24px auto", maxWidth: 500, width: "100%", display: "flex", justifyContent: "center" }}>
              {coords && (
                <SchoolMap coords={coords} schools={schools} />
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // DESKTOP LAYOUT
  return (
    <div style={{ minHeight: "100vh", width: "100vw", background: "#f5f5f5", position: "relative" }}>
      <div className="header-container">
        <img src="/PSA_logo.png" alt="PSA logo" className="logo" />
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
              onClick={() => setMenuOpen(open => !open)}
              aria-label="Open menu"
            >
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

      {isNarrow && menuOpen && (
        <div style={{
          position: "fixed",
          top: 110,
          right: "12%",
          background: "#c40c0c",
          borderRadius: 12,
          boxShadow: "0 4px 24px rgba(0,0,0,0.18)",
          padding: "12px 0",
          minWidth: 180,
          maxHeight: "60vh",
          overflowY: "auto",
          zIndex: 300
        }}>
          {buttons.map(btn => (
            <button
              key={btn.path}
              className="home-btn"
              onClick={() => {
                setMenuOpen(false);
                navigate(btn.path);
              }}
            >
              {btn.label}
            </button>
          ))}
        </div>
      )}

      <div style={{ width: "100vw", height: 310, overflow: "hidden", marginTop: 0 }}>
        <img
          src={images[bgIndex]}
          alt=""
          style={{ width: "100vw", height: 310, objectFit: "cover", display: "block" }}
        />
      </div>

      <div
        style={{
          position: "absolute",
          left: "50%",
          top: 140,
          transform: "translateX(-50%)",
          zIndex: 210,
          fontWeight: 900,
          fontSize: "3vw",
          color: "#fff",
          letterSpacing: 1,
          textShadow: "2px 4px 8px rgba(0,0,0,1)",
          maxWidth: "90vw",
          minWidth: "200px",
          wordBreak: "break-word",
          lineHeight: 1.1,
          textAlign: "center",
          pointerEvents: "none"
        }}
      >
        SCHOOL FINDER
      </div>

      <div style={{ margin: "32px auto 0 auto", maxWidth: 500, padding: "0 8px", marginTop: 60, display: "flex", flexDirection: "column", alignItems: "center" }}>
        <form onSubmit={handleSubmit} style={{ textAlign: "center", width: "100%" }}>
          <input
            className="schools-search-bar"
            type="text"
            value={address}
            onChange={e => setAddress(e.target.value)}
            placeholder="Enter address or location"
          />
          <div style={{ margin: "16px 0", display: "flex", flexWrap: "wrap", justifyContent: "center" }}>
            {ALL_KEYWORDS.map(kw => (
              <label key={kw} className="schools-keyword-label">
                <input
                  type="checkbox"
                  checked={selectedKeywords.includes(kw)}
                  onChange={() => handleKeywordChange(kw)}
                />
                {kw}
              </label>
            ))}
          </div>
          <div style={{ display: "flex", justifyContent: "center", marginBottom: 24, width: "100%" }}>
            <button
              type="submit"
              className="home-btn"
              style={{
                maxWidth: 400,
                width: "100%",
                textAlign: "center",
                display: "flex",
                justifyContent: "center",
                alignItems: "center"
              }}
            >
              Find Schools
            </button>
          </div>
        </form>
        <div style={{ width: "100%", display: "flex", flexDirection: "column", alignItems: "center" }}>
          {schools.length > 0 && (
            <div className="schoolfinder-list" style={{ marginTop: 16, width: "100%", maxWidth: 500 }}>
              <h3 style={{ textAlign: "center", color: "#c40c0c" }}>Nearby Schools:</h3>
              <ul style={{ paddingLeft: 0, listStyle: "none" }}>
                {schools.map(s => (
                  <li key={s.place_id} style={{ marginBottom: 16, textAlign: "center" }}>
                    <label style={{ cursor: "pointer" }}>
                      <input
                        type="checkbox"
                        checked={selectedRouteSchools.includes(s.place_id)}
                        onChange={() => toggleRouteSchool(s.place_id)}
                        style={{ marginRight: 8 }}
                      />
                      <b>{s.name}</b><br />
                      {s.address}
                    </label>
                  </li>
                ))}
              </ul>
              <div style={{ margin: "16px 0", width: "100%" }}>
                <input
                  type="text"
                  className="schools-search-bar"
                  value={startAddress}
                  onChange={e => setStartAddress(e.target.value)}
                  placeholder="Enter starting address for route"
                  style={{ width: "100%" }}
                />
              </div>
              <button
                className="home-btn"
                style={{ margin: "16px auto", display: "block" }}
                onClick={handleCreateRoute}
                disabled={selectedRouteSchools.length < 2}
              >
                Create Route
              </button>
              {routeOrder && (
                <div style={{ marginTop: 16 }}>
                  <h4>Optimal Route Order:</h4>
                  <ol>
                    {routeOrder.map(pid => {
                      const school = schools.find(s => s.place_id === pid);
                      return (
                        <li key={pid}>
                          <b>{school?.name}</b> - {school?.address}
                        </li>
                      );
                    })}
                  </ol>
                </div>
              )}
            </div>
          )}
          <div style={{ margin: "24px auto", maxWidth: 500, width: "100%", display: "flex", justifyContent: "center" }}>
            {coords && (
              <SchoolMap coords={coords} schools={schools} />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}