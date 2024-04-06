import { Link } from "react-router-dom";
import { useLogout } from '../hooks/useLogout'
import { useAuthContext } from "../hooks/useAuthContext";


const Navbar = () => {
    const { logout } = useLogout()
    const { user } = useAuthContext()

    const handleClick = () => {
        logout()
    }

    const nav__link = [
       {
        path:'#',
        display:'Home'
       },     
       {
        path:'#',
        display:'Schedule'
       },          
       {
        path:'#',
        display:'Pricing'
       },     
    ]

    return ( 
        <header>
            <div className="container">
                <Link to="/">
                    <h1>Workout Buddy</h1>
                </Link>

                <nav>
                <div className="navigation">
                    <ul className="menu">
                        {
                            nav__link.map(item => (
                                <li className="nav__item">
                                    <a href={item.path}>
                                        {item.display}
                                    </a>
                                </li>
                            ))
                        }
                    </ul>
                </div>
                </nav>

                <nav>
                    {user && (
                    <div>
                        <span>{user.email}</span>
                        <button onClick={handleClick}>Log out</button>
                    </div>
                    )}
                    {!user && (
                    <div>
                        <button className="btn"><Link to="/login">Login</Link></button>
                        <button className="btn"><Link to="/signup">Sign up</Link></button>
                    </div>
                    )}
                </nav>
            </div>  
        </header>
     );
}
 
export default Navbar;