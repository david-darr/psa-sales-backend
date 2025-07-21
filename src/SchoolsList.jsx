import { useNavigate } from 'react-router-dom'
import { useEffect, useState, useRef } from 'react'



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

export default function SchoolsList() {
  const isMobile = useIsMobile()
  const isNarrow = useIsNarrow()
  const navigate = useNavigate()
  const [schools, setSchools] = useState([])
  const [search, setSearch] = useState('')
  const rowRefs = useRef({})

  useEffect(() => {
    fetch('/api/schools')
      .then(res => res.json())
      .then(setSchools)
  }, [])

  // When Enter is pressed in the search bar, scroll to the matching school
  function handleSearchKeyDown(e) {
    if (e.key === 'Enter') {
      const match = schools.find(
        s => s.name.toLowerCase() === search.trim().toLowerCase()
      )
      if (match && rowRefs.current[match.id]) {
        rowRefs.current[match.id].scrollIntoView({ behavior: 'smooth', block: 'center' })
      }
    }
  }

  return (
    <div>
      <div className="section-header">
        <button
          className="back-btn-global"
          onClick={() => navigate('/')}
        >
          ← Home
        </button>
        <h2 className="section-title">List of Schools</h2>
      </div>
      <div className="schools-list-container">
        <input
          className="schools-search-bar"
          type="text"
          placeholder="Type school name and press Enter..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={handleSearchKeyDown}
        />
        <div className="schools-table-scroll-container">
          <table className="schools-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Address</th>
                <th>Phone Number</th>
                <th>Contact Name</th>
                <th>Email</th>
              </tr>
            </thead>
            <tbody>
              {schools.map(s => (
                <tr
                  key={s.id}
                  ref={el => (rowRefs.current[s.id] = el)}
                >
                  <td>{s.name}</td>
                  <td>{s.address}</td>
                  <td>{s.phone}</td>
                  <td>{s.contact}</td>
                  <td>{s.email}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}