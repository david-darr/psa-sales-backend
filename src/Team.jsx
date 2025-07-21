import { useNavigate } from 'react-router-dom'

export default function Team() {
  const navigate = useNavigate()
  return (
    <div>
      <div className="section-header">
        <button
          className="back-btn-global"
          onClick={() => navigate('/')}
        >
          ← Home
        </button>
        <h2 className="section-title">Team</h2>
      </div>
      <div>
        <h1>
          Work In Progress
        </h1>
      </div>
    </div>
    
  )
}