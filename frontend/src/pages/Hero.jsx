import React from 'react'

const Hero = () => {
  return (
    <section>
        <div className="container">
            <div className="hero__wrapper">
                {/* ========== hero content ========== */}
                <div className="hero__content">
                    <h2>Exercise is the key to a Healthy Lifestyle</h2>
                    <p>
                        Lorem ipsum dolor, sit amet consectetur adipisicing elit. Nam quo minima quibusdam voluptas?
                    </p>

                    <div className="hero__btns">
                        <button className='register__btn'>Get Started</button>
                        <button className="watch__btn">
                            <span>
                                <i class="ri-play-fill"></i>
                            </span>
                        </button>
                    </div>
                </div>

                {/* ========== hero img ======== */}
                <div className="hero__img">
                    
                </div>
            </div>
        </div>
    </section>
  )
}

export default Hero