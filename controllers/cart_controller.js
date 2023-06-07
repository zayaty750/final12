import {mongo} from 'mongoose';
import Product from '../models/products_model.js';
import {Cart}
 from  "../models/cart-model.js";


const addCart = async (req, res, next) => {

    const product_id = req.params.id;
    
    const product = await Product.findById(product_id);
      if(product)
      {
        let cart = new Cart(req.session.cart ? req.session.cart : {});
        cart.add(product, product_id);
        console.log()
        req.session.cart = cart;
        console.log(req.session.cart);
        res.redirect('/user/products');
      }
      else
      {
        res.redirect('/user/products',);
      }
      
  };


const getCart = async (req, res,next) =>
{
  let cart = new Cart(req.session.cart ? req.session.cart : {});
  if(cart.totalQty != 0)
  {
    console.log(cart);
    res.render('pages/cart',{ products: cart.generateArray() ,subtotal : cart.totalPrice,qt: cart.totalQty ,user:  (req.session.user === undefined ? "" : req.session.user) });
  }
  else
  {
    console.log("done");
    res.render('pages/cart',{ products: undefined ,subtotal : cart.totalPrice , qt: cart.totalQty , user:  (req.session.user === undefined ? "" : req.session.user) });
  }
};


  export {addCart,getCart} ;